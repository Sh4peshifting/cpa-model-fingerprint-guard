// Package cpa adapts the native CLIProxyAPI RPC contract to the guard.
package cpa

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bul1horn/cpa-model-fingerprint-guard/internal/fingerprint"
	"github.com/bul1horn/cpa-model-fingerprint-guard/internal/guard"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type Call func(context.Context, string, any, any) error

type Host struct {
	call   Call
	native bool
	marker string
}

const (
	probeHeader    = "X-Model-Fingerprint-Guard-Probe"
	internalSource = "plugin_host_model_callback"
)

func NewHost(call Call, native bool) (*Host, error) {
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, err
	}
	return &Host{call: call, native: native, marker: hex.EncodeToString(token[:])}, nil
}

func (h *Host) List(ctx context.Context) ([]guard.Auth, error) {
	var result struct {
		Files []pluginapi.HostAuthFileEntry `json:"files"`
	}
	if err := h.call(ctx, pluginabi.MethodHostAuthList, struct{}{}, &result); err != nil {
		return nil, err
	}
	auths := make([]guard.Auth, 0, len(result.Files))
	for _, a := range result.Files {
		if a.ID == "" || a.RuntimeOnly || a.Source != "file" || a.Path == "" {
			continue
		}
		auths = append(auths, h.auth(a))
	}
	return auths, nil
}

func (h *Host) auth(a pluginapi.HostAuthFileEntry) guard.Auth {
	format := nativeFormat(a.Provider, a.AccountType)
	// Only keep values required by scheduling. In particular, discard Account,
	// Note, Email, BaseURL and any raw status messages from the host.
	snapshot := fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%d\x00%d\x00%d",
		a.AuthIndex, a.Path, a.Provider, a.Size, a.ModTime.UnixNano(), a.CreatedAt.UnixNano(), a.LastRefresh.UnixNano())
	digest := sha256.Sum256([]byte(snapshot))
	return guard.Auth{
		ID: a.ID, Name: a.Name, Provider: strings.ToLower(a.Provider),
		Disabled:  a.Disabled || a.Status == "disabled",
		Cooling:   a.Unavailable || a.NextRetryAfter.After(time.Now()),
		Probeable: h.native && format != "", ProbeFormat: format, Version: hex.EncodeToString(digest[:]),
	}
}

func nativeFormat(provider, kind string) string {
	if kind != "oauth" {
		return ""
	}
	switch strings.ToLower(provider) {
	case "codex":
		return "openai-response"
	case "claude":
		return "claude"
	case "gemini-cli":
		return "openai"
	default:
		return ""
	}
}

func (h *Host) CanMutate() bool { return false }

func (h *Host) Disable(context.Context, guard.Auth, guard.Abnormal) error {
	return guard.ErrUnavailable
}

func (h *Host) Recover(context.Context, guard.Auth, guard.Abnormal) error {
	return guard.ErrUnavailable
}

func (h *Host) Sample(ctx context.Context, p guard.Probe, protocol string, body []byte) (fingerprint.Response, error) {
	if !h.native || p.ID == "" || p.Model == "" || p.ProbeFormat == "" || p.ProbeFormat != protocol {
		return fingerprint.Response{}, guard.ErrUnavailable
	}
	auths, err := h.List(ctx)
	if err != nil {
		return fingerprint.Response{}, err
	}
	var valid bool
	for _, a := range auths {
		if a.ID == p.ID && a.Version == p.Version && a.Provider == p.Provider && !a.Disabled && a.Probeable {
			valid = true
			break
		}
	}
	if !valid {
		return fingerprint.Response{}, guard.ErrUnavailable
	}
	req := pluginapi.HostModelExecutionRequest{
		EntryProtocol: protocol, ExitProtocol: protocol, Model: p.Model,
		Body: body, Headers: http.Header{probeHeader: []string{h.marker}},
		ForcedProvider: p.Provider, AuthID: p.ID,
	}
	var result pluginapi.HostModelExecutionResponse
	if err := h.call(ctx, pluginabi.MethodHostModelExecute, req, &result); err != nil {
		var rpcErr *pluginabi.Error
		if errors.As(err, &rpcErr) {
			// The body is only inspected for overload. The detector never stores it.
			return fingerprint.Response{Status: rpcErr.HTTPStatus, Body: []byte(rpcErr.Message)}, err
		}
		return fingerprint.Response{}, err
	}
	return fingerprint.Response{Status: result.StatusCode, Body: result.Body}, nil
}

func (h *Host) ownProbe(meta map[string]any, headers http.Header) bool {
	return stringMeta(meta, "source") == internalSource && stringMeta(meta, "pinned_auth_id") != "" &&
		headers.Get(probeHeader) == h.marker
}

func stringMeta(meta map[string]any, key string) string {
	v, _ := meta[key].(string)
	return v
}
