// Package fingerprint runs the pinned lm-detector challenge and classifier locally.
package fingerprint

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	lmfpd "github.com/Ikaleio/lm-detector/sdk/go"
	"github.com/bul1horn/cpa-model-fingerprint-guard/internal/guard"
)

type Transport interface {
	Sample(ctx context.Context, probe guard.Probe, protocol string, body []byte) (Response, error)
}

type Response struct {
	Status int
	Body   []byte
}

type Detector struct {
	active    atomic.Pointer[reference]
	transport Transport
}

type reference struct {
	engine  *lmfpd.Detector
	models  []string
	builtAt time.Time
	source  string
}

func Open(ctx context.Context, dir string, transport Transport) (*Detector, error) {
	source := "local"
	if dir == "" {
		source = "embedded"
		var err error
		var cleanup func()
		dir, cleanup, err = embeddedReference()
		if err != nil {
			return nil, err
		}
		defer cleanup()
	}
	ref, err := loadReference(ctx, dir, source)
	if err != nil {
		return nil, err
	}
	d := &Detector{transport: transport}
	d.active.Store(ref)
	return d, nil
}

func loadReference(ctx context.Context, dir, source string) (*reference, error) {
	// Absolute local paths force the SDK's offline load path and disable its
	// background revalidation and remote data-source fallback.
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	engine, err := lmfpd.Load(ctx, lmfpd.LoadOptions{Sources: []string{dir}})
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(dir, "unified_bank.json"))
	if err != nil {
		return nil, err
	}
	var bank struct {
		Models []struct {
			ID string `json:"id"`
		} `json:"models"`
	}
	if err := json.Unmarshal(data, &bank); err != nil {
		return nil, err
	}
	models := make([]string, 0, len(bank.Models))
	for _, m := range bank.Models {
		models = append(models, m.ID)
	}
	slices.Sort(models)
	builtAt, err := time.Parse(time.RFC3339Nano, engine.BuiltAt())
	if err != nil {
		return nil, errors.New("invalid reference build time")
	}
	return &reference{engine: engine, models: models, builtAt: builtAt.UTC(), source: source}, nil
}

func (d *Detector) Models() []string { return slices.Clone(d.active.Load().models) }

func (d *Detector) Check(ctx context.Context, p guard.Probe) guard.Result {
	ref := d.active.Load()
	r := check(ctx, p, ref, d.transport)
	r.ReferenceBuild = ref.builtAt.Format(time.RFC3339Nano)
	return r
}

func check(ctx context.Context, p guard.Probe, ref *reference, transport Transport) guard.Result {
	if _, supported := slices.BinarySearch(ref.models, p.Expected); !supported {
		return guard.Result{Status: guard.Unsupported, Reason: "unknown_reference"}
	}
	api, protocol := protocolFormat(p.ProbeFormat)
	if protocol == "" {
		return guard.Result{Status: guard.Unsupported, Reason: "unsupported_route"}
	}
	challenges, err := lmfpd.GenerateChallenges(3)
	if err != nil {
		return guard.Result{Status: guard.Inconclusive, Reason: "challenge_failed"}
	}
	opts := lmfpd.DetectConfig{
		BaseURL: "https://unused.invalid", APIKey: "unused", API: api,
		Model: p.Model, Strict: true, NoStream: true,
	}
	outputs := make([]lmfpd.Output, 0, len(challenges))
	for _, challenge := range challenges {
		if ctx.Err() != nil {
			return guard.Result{Status: guard.Cancelled}
		}
		req, err := lmfpd.BuildRequest(opts, challenge.Prompt)
		if err != nil {
			return guard.Result{Status: guard.Unsupported, Reason: "invalid_probe_config"}
		}
		payload, err := json.Marshal(req.Body)
		if err != nil {
			return guard.Result{Status: guard.Inconclusive, Reason: "challenge_failed"}
		}
		// Only send the SDK-built request body. The SDK's placeholder URL and
		// headers are never used. The host owns credentials and transport.
		sampleCtx, cancel := context.WithTimeout(ctx, p.Timeout)
		reply, err := transport.Sample(sampleCtx, p, protocol, payload)
		callErr := sampleCtx.Err()
		cancel()
		if ctx.Err() != nil {
			return guard.Result{Status: guard.Cancelled}
		}
		if errors.Is(callErr, context.DeadlineExceeded) {
			return guard.Result{Status: guard.Transient, Reason: "timeout"}
		}
		if err != nil || reply.Status < 200 || reply.Status > 299 {
			return guard.Result{Status: guard.Transient, Reason: "upstream_failure", Overloaded: isOverload(reply.Status, reply.Body)}
		}
		text, status := decodeSample(protocol, reply.Body)
		if status != "" {
			return guard.Result{Status: status, Reason: "invalid_sample", Overloaded: isOverload(reply.Status, reply.Body)}
		}
		outputs = append(outputs, lmfpd.Output{Text: text, ExpectedCount: challenge.ExpectedCount})
	}
	analysis, err := ref.engine.Analyze(outputs, true)
	if err != nil {
		return guard.Result{Status: guard.Inconclusive, Reason: "invalid_samples"}
	}
	return classify(analysis, p.Expected, p.Probability)
}

func classify(a *lmfpd.Analysis, expected string, threshold float64) guard.Result {
	r := guard.Result{
		Status: guard.Inconclusive, Detected: a.Prediction,
		Score: a.RankingScore, Probability: a.Probability, Reason: "insufficient_evidence",
	}
	if a.Decision != "scored" || a.UsedOutputs != 3 || a.Prediction == "" ||
		a.ProbabilityStatus != "reference_calibrated" || a.Probability == nil ||
		a.Evidence.Insufficient || !(*a.Probability >= threshold && *a.Probability <= 1) {
		return r
	}
	r.Reason = ""
	r.Status = guard.Mismatch
	if a.Prediction == expected {
		r.Status = guard.Match
	}
	return r
}

func isOverload(status int, body []byte) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	text := strings.ToLower(string(body[:min(len(body), 16<<10)]))
	return strings.Contains(text, "server_is_overloaded") || strings.Contains(text, "servers are currently overloaded")
}

func protocolFormat(format string) (lmfpd.API, string) {
	switch format {
	case "openai-response":
		return lmfpd.APIResponses, format
	case "openai":
		return lmfpd.APIChatCompletions, format
	case "claude":
		return lmfpd.APIMessages, format
	default:
		return "", ""
	}
}
