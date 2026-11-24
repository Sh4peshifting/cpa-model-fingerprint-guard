package main

import "github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"

func resourceRoutes() []pluginapi.ResourceRoute {
	return nil
}

func resource(pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	return errorResponse(404, "资源不存在")
}
