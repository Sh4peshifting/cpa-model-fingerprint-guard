package fingerprint

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	lmfpd "github.com/Ikaleio/lm-detector/sdk/go"
	"github.com/Sh4peshifting/cpa-model-fingerprint-guard/internal/guard"
)

func TestClassificationRequiresValidCalibratedRound(t *testing.T) {
	p := .95
	a := &lmfpd.Analysis{Decision: "scored", UsedOutputs: 3, Prediction: "reference", Probability: &p, ProbabilityStatus: "reference_calibrated"}
	if got := classify(a, "expected", .9); got.Status != guard.Mismatch {
		t.Fatalf("classification = %+v", got)
	}
	if got := classify(a, "reference", .9); got.Status != guard.Match {
		t.Fatalf("classification = %+v", got)
	}
	if got := classify(a, "expected", .99); got.Status != guard.Inconclusive {
		t.Fatalf("classification = %+v", got)
	}
	a.UsedOutputs = 2
	if got := classify(a, "expected", .9); got.Status != guard.Inconclusive {
		t.Fatalf("classification = %+v", got)
	}
}

func TestJSONSampleValidation(t *testing.T) {
	for _, tc := range []struct {
		protocol, body, text string
		status               guard.Status
	}{
		{"openai", `{"choices":[{"finish_reason":"stop","message":{"content":"1,2"}}]}`, "1,2", ""},
		{"openai", `{"choices":[{"finish_reason":"length","message":{"content":"1,2"}}]}`, "", guard.Inconclusive},
		{"claude", `{"stop_reason":"end_turn","content":[{"type":"text","text":"1,2"}]}`, "1,2", ""},
		{"openai-response", `{"status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"1,2"}]}]}`, "1,2", ""},
		{"openai-response", `{"error":{"code":"server_is_overloaded"}}`, "", guard.Transient},
	} {
		if text, status := decodeSample(tc.protocol, []byte(tc.body)); text != tc.text || status != tc.status {
			t.Errorf("%s: got %q, %q", tc.protocol, text, status)
		}
	}
}

type sampleFunc func(context.Context, guard.Probe, string, []byte) (Response, error)

func (f sampleFunc) Sample(ctx context.Context, p guard.Probe, protocol string, body []byte) (Response, error) {
	return f(ctx, p, protocol, body)
}

func TestPinnedProbeWithRealReference(t *testing.T) {
	dir := os.Getenv("MFG_TEST_REFERENCE")
	if dir == "" {
		t.Skip("set MFG_TEST_REFERENCE to the pinned lm-detector data directory")
	}
	seen := map[string]bool{}
	probe := guard.Probe{Auth: guard.Auth{ID: "a", Provider: "codex", ProbeFormat: "openai-response"}, Model: "alias", Timeout: time.Second, Probability: .9}
	d, err := Open(t.Context(), dir, sampleFunc(func(_ context.Context, p guard.Probe, protocol string, body []byte) (Response, error) {
		var request map[string]any
		if err := json.Unmarshal(body, &request); err != nil {
			t.Fatal(err)
		}
		if p.ID != "a" || p.Model != "alias" || protocol != "openai-response" || request["model"] != "alias" || seen[string(body)] {
			t.Fatalf("unlocked or duplicate probe: %+v", p)
		}
		seen[string(body)] = true
		return Response{Status: 200, Body: []byte(`{"status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"1,2"}]}]}`)}, nil
	}))
	if err != nil || len(d.Models()) == 0 {
		t.Fatalf("load reference: %v", err)
	}
	probe.Expected = d.Models()[0]
	if got := d.Check(t.Context(), probe); len(seen) != 3 || got.Status != guard.Inconclusive {
		t.Fatalf("samples = %d, result = %+v", len(seen), got)
	}
}
