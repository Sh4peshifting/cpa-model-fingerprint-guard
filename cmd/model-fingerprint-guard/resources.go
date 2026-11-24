package main

import (
	"embed"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

//go:embed web/index.html web/app.js web/style.css
var web embed.FS

var contentTypes = map[string]string{
	"index.html": "text/html; charset=utf-8",
	"app.js":     "text/javascript; charset=utf-8",
	"style.css":  "text/css; charset=utf-8",
}

func resourceRoutes() []pluginapi.ResourceRoute {
	return []pluginapi.ResourceRoute{
		{Path: "index.html", Menu: "模型指纹守卫", Description: "检测、隔离和审计认证文件"},
		{Path: "app.js"},
		{Path: "style.css"},
	}
}

func resource(r pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	name := strings.TrimPrefix(r.Path, resPath+"/")
	contentType, ok := contentTypes[name]
	if !ok || r.Method != "GET" {
		return errorResponse(404, "资源不存在")
	}
	body, err := web.ReadFile("web/" + name)
	if err != nil {
		return errorResponse(500, "无法读取页面资源")
	}
	return pluginapi.ManagementResponse{
		StatusCode: 200, Body: body,
		Headers: http.Header{
			"Content-Type":            []string{contentType},
			"Content-Security-Policy": []string{"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'none'; base-uri 'none'"},
			"Cache-Control":           []string{"no-store"},
			"Referrer-Policy":         []string{"no-referrer"},
			"X-Content-Type-Options":  []string{"nosniff"},
		},
	}
}
