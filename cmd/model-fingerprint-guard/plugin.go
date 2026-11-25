package main

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/Sh4peshifting/cpa-model-fingerprint-guard/internal/cpa"
	"github.com/Sh4peshifting/cpa-model-fingerprint-guard/internal/fingerprint"
	"github.com/Sh4peshifting/cpa-model-fingerprint-guard/internal/guard"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const pluginID = "model-fingerprint-guard"

var releaseVersion = "0.1.0-dev"

type runtime struct {
	*guard.Guard
	*cpa.Observer
	mu             sync.RWMutex
	host           *cpa.Host
	options        pluginOptions
	configRejected bool
	references     *fingerprint.Updater
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
	o, err := decodePluginOptions(req.Config)
	lifecycle.Lock()
	defer lifecycle.Unlock()
	if old := instance.Load(); old != nil {
		old.applyOptions(o, err)
		return registration(), nil
	}
	if err != nil {
		return nil, err
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
	updater := fingerprint.NewUpdater(d, o.StateDir, o.updateInterval())
	instance.Store(&runtime{Guard: g, Observer: cpa.NewObserver(g, h), host: h, options: o, references: updater})
	updater.Start()
	g.Start()
	return registration(), nil
}

func registration() any {
	return map[string]any{
		"schema_version": pluginabi.SchemaVersion,
		"metadata": pluginapi.Metadata{
			Name: "模型指纹守卫", Version: releaseVersion, Author: "Sh4peshifting",
			GitHubRepository: "https://github.com/Sh4peshifting/cpa-model-fingerprint-guard",
			ConfigFields:     configFields(),
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
		current.references.Close()
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
