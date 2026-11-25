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
	"sync"
	"sync/atomic"
	"time"

	lmfpd "github.com/Ikaleio/lm-detector/sdk/go"
	"github.com/Sh4peshifting/cpa-model-fingerprint-guard/internal/guard"
)

type Transport interface {
	Sample(ctx context.Context, probe guard.Probe, protocol string, body []byte) (Response, error)
}

type Response struct {
	Status        int
	Body          []byte
	CooldownUntil time.Time
}

type Detector struct {
	active    atomic.Pointer[reference]
	transport Transport
}

const astraModel = "gpt-6-astra"

type reference struct {
	engine         *lmfpd.Detector
	models         []string
	builtAt        time.Time
	source         string
	sharedAstraSol bool
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
			ID          string `json:"id"`
			DisplayName string `json:"display_name"`
		} `json:"models"`
	}
	if err := json.Unmarshal(data, &bank); err != nil {
		return nil, err
	}
	models := make([]string, 0, len(bank.Models))
	var combinedAstraSol bool
	for _, m := range bank.Models {
		models = append(models, m.ID)
		if m.ID == astraModel && strings.Contains(m.DisplayName, "6.1-sol") {
			combinedAstraSol = true
		}
	}
	slices.Sort(models)
	builtAt, err := time.Parse(time.RFC3339Nano, engine.BuiltAt())
	if err != nil {
		return nil, errors.New("invalid reference build time")
	}
	_, separateSol := slices.BinarySearch(models, guard.ModelGPT61Sol)
	return &reference{
		engine: engine, models: models, builtAt: builtAt.UTC(), source: source,
		sharedAstraSol: combinedAstraSol && !separateSol,
	}, nil
}

func (d *Detector) Models() []string { return slices.Clone(d.active.Load().models) }

func (d *Detector) Check(ctx context.Context, p guard.Probe) guard.Result {
	ref := d.active.Load()
	r := check(ctx, p, ref, d.transport)
	r.ReferenceBuild = ref.builtAt.Format(time.RFC3339Nano)
	return r
}

func check(ctx context.Context, p guard.Probe, ref *reference, transport Transport) guard.Result {
	expected := ref.expectedModel(p.Expected)
	if _, supported := slices.BinarySearch(ref.models, expected); !supported {
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
	outputs, failure := sampleRound(ctx, p, transport, protocol, opts, challenges)
	if failure.Status != "" {
		return failure
	}
	analysis, err := ref.engine.Analyze(outputs, true)
	if err != nil {
		return guard.Result{Status: guard.Inconclusive, Reason: "invalid_samples"}
	}
	return ref.classify(analysis, expected, p.Probability)
}

func (ref *reference) expectedModel(expected string) string {
	if expected == guard.ModelGPT61Sol && ref.sharedAstraSol {
		return astraModel
	}
	return expected
}

func (ref *reference) classify(analysis *lmfpd.Analysis, expected string, threshold float64) guard.Result {
	r := classify(analysis, expected, threshold)
	if ref.sharedAstraSol && r.Detected == astraModel {
		r.DetectedClass = astraModel + " / " + guard.ModelGPT61Sol
	}
	return r
}
func sampleRound(ctx context.Context, p guard.Probe, transport Transport, protocol string, opts lmfpd.DetectConfig, challenges []lmfpd.Challenge) ([]lmfpd.Output, guard.Result) {
	outputs := make([]lmfpd.Output, len(challenges))
	if !p.ParallelChallenges {
		for i, challenge := range challenges {
			output, failure := sampleChallenge(ctx, p, transport, protocol, opts, challenge)
			if failure.Status != "" {
				return nil, failure
			}
			outputs[i] = output
		}
		return outputs, guard.Result{}
	}
	failures := make([]guard.Result, len(challenges))
	var wg sync.WaitGroup
	for i, challenge := range challenges {
		wg.Go(func() {
			outputs[i], failures[i] = sampleChallenge(ctx, p, transport, protocol, opts, challenge)
		})
	}
	wg.Wait()
	if ctx.Err() != nil {
		return nil, guard.Result{Status: guard.Cancelled}
	}

	// Keep an actual gateway failure and any CPA deadline from this round.
	var failure guard.Result
	var cooldown time.Time
	for _, current := range failures {
		if current.Status == "" {
			continue
		}
		if current.CooldownUntil.After(cooldown) {
			cooldown = current.CooldownUntil
		}
		if failure.Status == "" || !failure.GatewayFailure() &&
			(current.GatewayFailure() || current.CooldownUntil.After(failure.CooldownUntil)) {
			failure = current
		}
	}
	failure.CooldownUntil = cooldown
	return outputs, failure
}

func sampleChallenge(ctx context.Context, p guard.Probe, transport Transport, protocol string, opts lmfpd.DetectConfig, challenge lmfpd.Challenge) (lmfpd.Output, guard.Result) {
	var output lmfpd.Output
	if ctx.Err() != nil {
		return output, guard.Result{Status: guard.Cancelled}
	}
	req, err := lmfpd.BuildRequest(opts, challenge.Prompt)
	if err != nil {
		return output, guard.Result{Status: guard.Unsupported, Reason: "invalid_probe_config"}
	}
	payload, err := json.Marshal(req.Body)
	if err != nil {
		return output, guard.Result{Status: guard.Inconclusive, Reason: "challenge_failed"}
	}
	// Only send the SDK-built request body. The host owns credentials and transport.
	sampleCtx, cancel := context.WithTimeout(ctx, p.Timeout)
	reply, err := transport.Sample(sampleCtx, p, protocol, payload)
	callErr := sampleCtx.Err()
	cancel()
	if ctx.Err() != nil {
		return output, guard.Result{Status: guard.Cancelled}
	}
	if errors.Is(callErr, context.DeadlineExceeded) {
		return output, guard.Result{Status: guard.Transient, Reason: "timeout"}
	}
	if err != nil || reply.Status < 200 || reply.Status > 299 {
		return output, guard.Result{
			Status: guard.Transient, Reason: "upstream_failure", HTTPStatus: reply.Status,
			Overloaded: isOverload(reply.Status, reply.Body), CooldownUntil: reply.CooldownUntil,
		}
	}
	text, status := decodeSample(protocol, reply.Body)
	if status != "" {
		return output, guard.Result{Status: status, Reason: "invalid_sample", Overloaded: isOverload(reply.Status, reply.Body)}
	}
	return lmfpd.Output{Text: text, ExpectedCount: challenge.ExpectedCount}, guard.Result{}
}

func classify(a *lmfpd.Analysis, expected string, threshold float64) guard.Result {
	r := guard.Result{
		Status: guard.Inconclusive, Detected: a.Prediction,
		Score: a.RankingScore, Probability: a.Probability, Reason: "insufficient_evidence",
	}
	// The pinned SDK leaves Evidence.Insufficient set even on calibrated results.
	if a.Decision != "scored" || a.UsedOutputs != 3 || a.Prediction == "" ||
		a.ProbabilityStatus != "reference_calibrated" || a.Probability == nil ||
		!(*a.Probability >= threshold && *a.Probability <= 1) {
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
