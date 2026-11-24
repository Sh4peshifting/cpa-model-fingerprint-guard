package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bul1horn/cpa-model-fingerprint-guard/internal/guard"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const (
	apiPath = "/v0/management/" + pluginID
	resPath = "/v0/resource/plugins/" + pluginID
)

func routes() any {
	return pluginapi.ManagementRegistrationResponse{
		Routes: []pluginapi.ManagementRoute{
			{Method: "GET", Path: apiPath + "/state"},
			{Method: "PUT", Path: apiPath + "/settings"},
			{Method: "PUT", Path: apiPath + "/auth-settings"},
			{Method: "POST", Path: apiPath + "/action"},
		},
		Resources: resourceRoutes(),
	}
}

func (p *runtime) manage(r pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	if strings.HasPrefix(r.Path, resPath+"/") {
		return resource(r)
	}
	switch {
	case r.Method == "GET" && r.Path == apiPath+"/state":
		return jsonResponse(200, p.View())
	case r.Method == "PUT" && r.Path == apiPath+"/settings":
		var in struct {
			Revision uint64       `json:"revision"`
			Settings guard.Config `json:"settings"`
		}
		if !decodeManagement(r.Body, &in) {
			return errorResponse(400, "配置请求格式错误")
		}
		if err := in.Settings.Validate(); err != nil {
			return errorResponse(400, err.Error())
		}
		return resultResponse(p.UpdateConfig(in.Revision, in.Settings))
	case r.Method == "PUT" && r.Path == apiPath+"/auth-settings":
		var in struct {
			Revision uint64                    `json:"revision"`
			Auths    map[string]guard.Override `json:"auths"`
		}
		if !decodeManagement(r.Body, &in) || len(in.Auths) == 0 || len(in.Auths) > 250 {
			return errorResponse(400, "一次可设置 1 至 250 项认证")
		}
		// Validate provided fields before applying the revision-checked transaction.
		check := guard.DefaultConfig()
		check.Auths = in.Auths
		if err := check.Validate(); err != nil {
			return errorResponse(400, err.Error())
		}
		return resultResponse(p.UpdateAuths(in.Revision, in.Auths))
	case r.Method == "POST" && r.Path == apiPath+"/action":
		var in struct {
			Action string   `json:"action"`
			IDs    []string `json:"ids"`
		}
		if !decodeManagement(r.Body, &in) || len(in.IDs) == 0 || len(in.IDs) > 250 {
			return errorResponse(400, "一次可操作 1 至 250 项认证")
		}
		switch in.Action {
		case "check", "isolate", "release", "recover":
		default:
			return errorResponse(400, "未知操作")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		perAuth := make(map[string]string, len(in.IDs))
		for _, id := range in.IDs {
			if _, done := perAuth[id]; !done {
				perAuth[id] = publicError(p.Act(ctx, in.Action, id))
			}
		}
		return jsonResponse(200, map[string]any{"results": perAuth})
	default:
		return errorResponse(404, "管理接口不存在")
	}
}

func decodeManagement(body []byte, out any) bool {
	if len(body) == 0 || len(body) > 1<<20 {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	return dec.Decode(out) == nil && dec.Decode(new(any)) == io.EOF
}

func resultResponse(err error) pluginapi.ManagementResponse {
	switch {
	case err == nil:
		return jsonResponse(200, map[string]bool{"ok": true})
	case errors.Is(err, guard.ErrConflict):
		return errorResponse(409, publicError(err))
	case errors.Is(err, guard.ErrUnknownAuth):
		return errorResponse(404, publicError(err))
	default:
		return errorResponse(500, publicError(err))
	}
}

func publicError(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, guard.ErrUnknownAuth), errors.Is(err, guard.ErrUnavailable), errors.Is(err, guard.ErrConflict):
		return err.Error()
	default:
		return "操作失败，请检查守卫状态或宿主日志"
	}
}

func errorResponse(status int, message string) pluginapi.ManagementResponse {
	return jsonResponse(status, map[string]string{"error": message})
}

func jsonResponse(status int, data any) pluginapi.ManagementResponse {
	body, err := json.Marshal(data)
	if err != nil {
		status = 500
		body = []byte(`{"error":"无法编码管理响应"}`)
	}
	return pluginapi.ManagementResponse{
		StatusCode: status, Body: body,
		Headers: http.Header{
			"Content-Type":           []string{"application/json; charset=utf-8"},
			"Cache-Control":          []string{"no-store"},
			"X-Content-Type-Options": []string{"nosniff"},
		},
	}
}
