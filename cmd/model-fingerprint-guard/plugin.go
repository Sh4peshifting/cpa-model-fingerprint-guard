package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/bul1horn/cpa-model-fingerprint-guard/internal/cpa"
	"github.com/bul1horn/cpa-model-fingerprint-guard/internal/fingerprint"
	"github.com/bul1horn/cpa-model-fingerprint-guard/internal/guard"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"go.yaml.in/yaml/v3"
)

const pluginID = "model-fingerprint-guard"

var releaseVersion = "0.1.0-dev"

type pluginOptions struct {
	Enabled      bool         `yaml:"enabled"`
	Priority     int          `yaml:"priority"`
	Store        yaml.Node    `yaml:"store"`
	StateDir     string       `yaml:"state-dir"`
	ReferenceDir string       `yaml:"reference-dir"`
	Native       bool         `yaml:"native-diagnostics"`
	Settings     guard.Config `yaml:"settings"`
}

type runtime struct {
	*guard.Guard
	*cpa.Observer
	options pluginOptions
}

var (
	instance  atomic.Pointer[runtime]
	lifecycle sync.Mutex
)

func loadPlugin(input []byte, call cpa.Call) (any, error) {
	var req struct {
		Config []byte `json:"config_yaml"`
		Schema uint32 `json:"schema_version"`
	}
	if err := json.Unmarshal(input, &req); err != nil {
		return nil, err
	}
	if req.Schema != pluginabi.SchemaVersion {
		return nil, errors.New("requires the CLIProxyAPI v8.1.2 plugin schema")
	}
	o := pluginOptions{
		StateDir: ".model-fingerprint-guard", Settings: guard.DefaultConfig(),
	}
	if len(req.Config) > 0 {
		dec := yaml.NewDecoder(bytes.NewReader(req.Config))
		dec.KnownFields(true)
		if err := dec.Decode(&o); err != nil {
			return nil, fmt.Errorf("invalid plugin configuration: %w", err)
		}
		if err := dec.Decode(new(any)); err != io.EOF {
			return nil, errors.New("only one YAML document is allowed")
		}
	}
	if dir := os.Getenv("MODEL_FINGERPRINT_GUARD_STATE_DIR"); dir != "" {
		o.StateDir = dir
	}
	if o.StateDir == "" {
		return nil, errors.New("state-dir must be a local directory")
	}
	if err := o.Settings.Validate(); err != nil {
		return nil, err
	}

	lifecycle.Lock()
	defer lifecycle.Unlock()
	old := instance.Load()
	if old != nil {
		if old.options.StateDir != o.StateDir || old.options.ReferenceDir != o.ReferenceDir || old.options.Native != o.Native {
			return nil, errors.New("restart CLIProxyAPI to change state-dir, reference-dir, or native-diagnostics")
		}
		return registration(), nil
	}
	h, err := cpa.NewHost(call, o.Native)
	if err != nil {
		return nil, err
	}
	d, err := fingerprint.Open(context.Background(), o.ReferenceDir, h)
	if err != nil {
		return nil, err
	}
	g, err := guard.Open(filepath.Join(o.StateDir, "state.json"), o.Settings, h, d)
	if err != nil {
		return nil, err
	}
	instance.Store(&runtime{g, cpa.NewObserver(g, h), o})
	g.Start()
	return registration(), nil
}

func registration() any {
	return map[string]any{
		"schema_version": pluginabi.SchemaVersion,
		"metadata": pluginapi.Metadata{
			Name: "模型指纹守卫", Version: releaseVersion, Author: "bul1horn",
			GitHubRepository: "https://github.com/bul1horn/cpa-model-fingerprint-guard",
		},
		"capabilities": map[string]bool{
			"scheduler": true, "scheduler_across_priorities": true,
			"request_interceptor": true, "request_interceptor_omit_body_before": true,
			"request_interceptor_omit_body_after": true, "request_lifecycle_plugin": true,
			"usage_plugin": true, "response_stream_interceptor": true, "management_api": true,
		},
	}
}

func stopPlugin() {
	lifecycle.Lock()
	defer lifecycle.Unlock()
	if current := instance.Swap(nil); current != nil {
		current.Close()
	}
}

func dispatch(method string, data []byte, call cpa.Call) (any, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		return loadPlugin(data, call)
	case pluginabi.MethodPluginQuiesce, pluginabi.MethodPluginShutdown:
		stopPlugin()
		return struct{}{}, nil
	}
	p := instance.Load()
	if p == nil {
		return nil, errors.New("plugin instance unavailable")
	}
	switch method {
	case pluginabi.MethodSchedulerPick:
		return decodeRPC(data, func(r pluginapi.SchedulerPickRequest) any { return p.Pick(r) })
	case pluginabi.MethodRequestInterceptBefore:
		return pluginapi.RequestInterceptResponse{}, nil
	case pluginabi.MethodRequestInterceptAfter:
		return decodeRPC(data, func(r pluginapi.RequestInterceptRequest) any { return p.AfterAuth(r) })
	case pluginabi.MethodRequestComplete:
		return decodeRPC(data, func(r pluginapi.RequestCompletion) any {
			p.Observer.Complete(r)
			return struct{}{}
		})
	case pluginabi.MethodUsageHandle:
		return decodeRPC(data, func(r pluginapi.UsageRecord) any {
			p.Usage(r)
			return struct{}{}
		})
	case pluginabi.MethodResponseInterceptStreamChunk:
		return decodeRPC(data, func(r pluginapi.StreamChunkInterceptRequest) any {
			p.Chunk(r)
			return pluginapi.StreamChunkInterceptResponse{}
		})
	case pluginabi.MethodManagementRegister:
		return routes(), nil
	case pluginabi.MethodManagementHandle:
		return decodeRPC(data, func(r pluginapi.ManagementRequest) any { return p.manage(r) })
	default:
		return nil, errors.New("unknown plugin RPC method")
	}
}

func decodeRPC[T any](data []byte, fn func(T) any) (any, error) {
	var req T
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, err
	}
	return fn(req), nil
}
