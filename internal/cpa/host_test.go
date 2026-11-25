package cpa

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Sh4peshifting/cpa-model-fingerprint-guard/internal/guard"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestModelCooldownRequiresMatchingCPAResponse(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	message := `{"error":{"code":"model_cooldown","model":"business-alias","reset_seconds":31}}`
	for _, tc := range []struct {
		status  int
		message string
		model   string
		want    time.Time
	}{
		{http.StatusTooManyRequests, message, "business-alias", now.Add(31 * time.Second)},
		{http.StatusTooManyRequests, message, "other-alias", time.Time{}},
		{http.StatusBadGateway, message, "business-alias", time.Time{}},
		{http.StatusTooManyRequests, `{"error":{"code":"rate_limit_exceeded","model":"business-alias","reset_seconds":31}}`, "business-alias", time.Time{}},
	} {
		err := &pluginabi.Error{HTTPStatus: tc.status, Message: tc.message}
		if got := modelCooldownUntil(err, tc.model, now); !got.Equal(tc.want) {
			t.Errorf("modelCooldownUntil(%d, %s, %s) = %s, want %s", tc.status, tc.message, tc.model, got, tc.want)
		}
	}
}

func TestHostCallbackUsesPinAndRejectsChangedAuth(t *testing.T) {
	var calls int
	auth := pluginapi.HostAuthFileEntry{ID: "a", Name: "a.json", AuthIndex: "index", Source: "file", Path: "/fake/a.json", Provider: "codex", AccountType: "oauth"}
	h, err := NewHost(func(_ context.Context, method string, in, out any) error {
		switch method {
		case pluginabi.MethodHostAuthList:
			files := out.(*struct {
				Files []pluginapi.HostAuthFileEntry `json:"files"`
			})
			files.Files = []pluginapi.HostAuthFileEntry{auth}
		case pluginabi.MethodHostModelExecute:
			calls++
			req := in.(pluginapi.HostModelExecutionRequest)
			if req.AuthID != "a" || req.ForcedProvider != "codex" || req.Model != "a-model" || req.Stream {
				t.Fatalf("unlocked request: %+v", req)
			}
			*out.(*pluginapi.HostModelExecutionResponse) = pluginapi.HostModelExecutionResponse{StatusCode: 200}
		default:
			t.Fatalf("unexpected method %s", method)
		}
		return nil
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	p := guard.Probe{Auth: h.auth(auth), Model: "a-model"}
	if _, err := h.Sample(t.Context(), p, "openai-response", nil); err != nil || calls != 1 {
		t.Fatalf("probe = %v, calls = %d", err, calls)
	}
	auth.Size = 1
	if _, err := h.Sample(t.Context(), p, "openai-response", nil); err == nil || calls != 1 {
		t.Fatalf("changed credential dispatched, err = %v, calls = %d", err, calls)
	}
	headers := http.Header{}
	headers.Set(probeHeader, h.marker)
	if h.ownProbe(map[string]any{"pinned_auth_id": "a"}, headers) ||
		!h.ownProbe(map[string]any{"source": internalSource, "pinned_auth_id": "a"}, headers) {
		t.Fatal("probe marker did not require host-internal attribution")
	}
}
