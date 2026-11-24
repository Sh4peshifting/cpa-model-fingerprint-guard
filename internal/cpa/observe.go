package cpa

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"github.com/bul1horn/cpa-model-fingerprint-guard/internal/guard"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type Observer struct {
	Guard *guard.Guard
	Host  *Host
	mu    sync.Mutex
	parts map[string]*eventBuffer
}

type eventBuffer struct {
	auth, event string
	pending     []byte
}

func NewObserver(g *guard.Guard, h *Host) *Observer {
	return &Observer{Guard: g, Host: h, parts: map[string]*eventBuffer{}}
}

func (o *Observer) Pick(req pluginapi.SchedulerPickRequest) pluginapi.SchedulerPickResponse {
	if o.Host.ownProbe(req.Options.Metadata, http.Header(req.Options.Headers)) {
		return pluginapi.SchedulerPickResponse{}
	}
	var resp pluginapi.SchedulerPickResponse
	for _, a := range req.Candidates {
		if o.Guard.Isolated(a.ID) {
			resp.ExcludeCandidates = append(resp.ExcludeCandidates, a.ID)
		}
	}
	return resp
}

func (o *Observer) AfterAuth(r pluginapi.RequestInterceptRequest) pluginapi.RequestInterceptResponse {
	id := stringMeta(r.Metadata, "selected_auth_id")
	if !o.Host.ownProbe(r.Metadata, r.Headers) && !o.Guard.Begin(r.RequestID, id, correlation("selection", stringMeta(r.Metadata, "selection_id"), id), correlation("trace", r.TraceID, id)) {
		return pluginapi.RequestInterceptResponse{
			Terminate: true, TerminateScope: "credential", StatusCode: http.StatusServiceUnavailable,
			ResponseHeaders: http.Header{"Content-Type": []string{"application/json"}},
			ResponseBody:    []byte(`{"error":{"code":"model_fingerprint_quarantine","message":"Credential temporarily unavailable"}}`),
		}
	}
	return pluginapi.RequestInterceptResponse{}
}

func (o *Observer) Complete(req pluginapi.RequestCompletion) {
	o.mu.Lock()
	delete(o.parts, req.RequestID)
	o.mu.Unlock()
	o.Guard.Complete(req.RequestID)
}

func (o *Observer) Usage(r pluginapi.UsageRecord) {
	if !r.Failed || r.RequestID == "" || r.AuthID == "" {
		return
	}
	_, code, text, _ := parseError([]byte(r.Failure.Body), true)
	if code == "model_fingerprint_quarantine" {
		return
	}
	o.Guard.Observe(r.RequestID, r.AuthID, r.Alias, r.Failure.StatusCode, code, text,
		correlation("selection", r.SelectionID, r.AuthID), correlation("trace", r.TraceID, r.AuthID))
}

func correlation(kind, id, auth string) string {
	if id == "" || auth == "" {
		return ""
	}
	return kind + "\x00" + id + "\x00" + auth
}

func (o *Observer) Chunk(r pluginapi.StreamChunkInterceptRequest) {
	if r.RequestID == "" || r.ChunkIndex < 0 || len(r.Body) == 0 {
		return
	}
	id := stringMeta(r.Metadata, "selected_auth_id")
	if id == "" {
		id = o.Guard.SingleAuth(r.RequestID)
	}
	if id == "" {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	part := o.parts[r.RequestID]
	if part == nil || part.auth != id {
		part = &eventBuffer{auth: id}
		o.parts[r.RequestID] = part
	}
	part.feed(r.Body, func(status int, code, text string) {
		if status == 0 {
			status = http.StatusOK
		}
		o.Guard.Observe(r.RequestID, id, r.RequestedModel, status, code, text)
	})
	if len(part.pending) == 0 && part.event == "" {
		delete(o.parts, r.RequestID)
	}
}

const maxEventBytes = 16 << 10

func (b *eventBuffer) feed(data []byte, emit func(int, string, string)) {
	if len(b.pending)+len(data) > maxEventBytes {
		b.pending, b.event = nil, ""
		return
	}
	b.pending = append(b.pending, data...)
	for {
		line, rest, hasNewline := bytes.Cut(b.pending, []byte{'\n'})
		line = bytes.TrimSpace(line)
		if v, ok := bytes.CutPrefix(line, []byte("event:")); ok {
			name := string(bytes.TrimSpace(v))
			if !hasNewline && name != "error" && strings.HasPrefix("error", name) {
				return
			}
			b.event = name
		} else if payload, ok := bytes.CutPrefix(line, []byte("data:")); ok || bytes.HasPrefix(line, []byte("{")) {
			if !ok {
				payload = line
			}
			payload = bytes.TrimSpace(payload)
			if !hasNewline && !json.Valid(payload) && !bytes.Equal(payload, []byte("[DONE]")) {
				return
			}
			if status, code, text, valid := parseError(payload, b.event == "error"); valid {
				emit(status, code, text)
			}
		} else if len(line) == 0 {
			if hasNewline {
				b.event = ""
			}
		} else if !hasNewline && (bytes.HasPrefix([]byte("data:"), line) || bytes.HasPrefix([]byte("event:"), line)) {
			return
		}
		b.pending = rest
		if len(rest) == 0 {
			return
		}
	}
}

func parseError(body []byte, errorContext bool) (status int, code, text string, valid bool) {
	if len(body) > maxEventBytes {
		body = body[:maxEventBytes]
	}
	type fields struct {
		Code    string `json:"code"`
		Type    string `json:"type"`
		Message string `json:"message"`
		Status  int    `json:"status_code"`
	}
	var event struct {
		fields
		Error    json.RawMessage `json:"error"`
		Response struct {
			Error json.RawMessage `json:"error"`
		} `json:"response"`
	}
	if json.Unmarshal(body, &event) != nil {
		return 0, "", string(body), errorContext
	}
	raw := event.Error
	if len(raw) == 0 || string(raw) == "null" {
		raw = event.Response.Error
	}
	hasError := len(raw) > 0 && string(raw) != "null"
	if !hasError && !errorContext && event.Type != "error" && event.Type != "response.failed" {
		return 0, "", "", false
	}
	detail := fields{}
	if hasError && json.Unmarshal(raw, &detail) != nil {
		_ = json.Unmarshal(raw, &detail.Message)
	}
	code = detail.Code
	if code == "" {
		code = detail.Type
	}
	if code == "" {
		code = event.Code
	}
	text = detail.Message
	if text == "" {
		text = event.Message
	}
	status = detail.Status
	if status == 0 {
		status = event.Status
	}
	if text == "" && errorContext && !hasError {
		text = strings.TrimSpace(string(body))
	}
	return status, code, text, true
}
