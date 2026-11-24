//go:build cgo

package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct { void *ptr; size_t len; } guard_buffer;
typedef int (*host_call_fn)(void *, const char *, const uint8_t *, size_t, guard_buffer *);
typedef void (*buffer_free_fn)(void *, size_t);
typedef struct {
	uint32_t abi_version;
	void *host_ctx;
	host_call_fn call;
	buffer_free_fn free_buffer;
} guard_host_api;

typedef int (*plugin_call_fn)(char *, uint8_t *, size_t, guard_buffer *);
typedef void (*plugin_shutdown_fn)(void);
typedef struct {
	uint32_t abi_version;
	plugin_call_fn call;
	buffer_free_fn free_buffer;
	plugin_shutdown_fn shutdown;
} guard_plugin_api;

extern int guardPluginCall(char *, uint8_t *, size_t, guard_buffer *);
extern void guardPluginFree(void *, size_t);
extern void guardPluginShutdown(void);

static inline int guard_call_host(guard_host_api *host, const char *method, const void *req, size_t len, guard_buffer *out) {
	return host->call(host->host_ctx, method, req, len, out);
}

static inline void guard_free_host(guard_host_api *host, guard_buffer *out) {
	host->free_buffer(out->ptr, out->len);
}
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
)

const maxRPC = 64 << 20

var hostAPI atomic.Pointer[C.guard_host_api]

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.guard_host_api, plugin *C.guard_plugin_api) C.int {
	if host == nil || host.abi_version != C.uint32_t(pluginabi.ABIVersion) || host.call == nil || host.free_buffer == nil || plugin == nil {
		return 1
	}
	hostAPI.Store(host)
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.plugin_call_fn(C.guardPluginCall)
	plugin.free_buffer = C.buffer_free_fn(C.guardPluginFree)
	plugin.shutdown = C.plugin_shutdown_fn(C.guardPluginShutdown)
	return 0
}

//export guardPluginCall
func guardPluginCall(method *C.char, request *C.uint8_t, size C.size_t, out *C.guard_buffer) (rc C.int) {
	if out == nil || method == nil || size > maxRPC || request == nil && size != 0 {
		return 1
	}
	out.ptr, out.len = nil, 0
	defer func() {
		if recover() != nil {
			rc = 1
		}
	}()
	data, err := dispatch(C.GoString(method), C.GoBytes(unsafe.Pointer(request), C.int(size)), callHost)
	envelope := wireEnvelope{OK: err == nil}
	if err != nil {
		envelope.Error = pluginabi.NewError("model_fingerprint_guard", err.Error())
	} else {
		envelope.Result, err = json.Marshal(data)
		if err != nil {
			return 1
		}
	}
	response, err := json.Marshal(envelope)
	if err != nil {
		return 1
	}
	out.ptr, out.len = C.CBytes(response), C.size_t(len(response))
	if out.ptr == nil {
		return 1
	}
	return 0
}

//export guardPluginFree
func guardPluginFree(ptr unsafe.Pointer, _ C.size_t) {
	C.free(ptr)
}

//export guardPluginShutdown
func guardPluginShutdown() {
	stopPlugin()
	hostAPI.Store(nil)
}

type wireEnvelope struct {
	OK     bool             `json:"ok"`
	Result json.RawMessage  `json:"result,omitempty"`
	Error  *pluginabi.Error `json:"error,omitempty"`
}

func callHost(ctx context.Context, method string, request, out any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	host := hostAPI.Load()
	if host == nil {
		return errors.New("host callback unavailable")
	}
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	cmd := C.CString(method)
	defer C.free(unsafe.Pointer(cmd))
	data := C.CBytes(body)
	defer C.free(data)
	var response C.guard_buffer
	rc := C.guard_call_host(host, cmd, data, C.size_t(len(body)), &response)
	if response.ptr != nil {
		defer C.guard_free_host(host, &response)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if rc != 0 || response.ptr == nil || response.len > maxRPC {
		return errors.New("host callback failed")
	}
	var envelope wireEnvelope
	if err := json.Unmarshal(C.GoBytes(response.ptr, C.int(response.len)), &envelope); err != nil {
		return errors.New("invalid host callback envelope")
	}
	if !envelope.OK {
		if envelope.Error != nil {
			return envelope.Error
		}
		return errors.New("host callback rejected")
	}
	if out != nil {
		if err := json.Unmarshal(envelope.Result, out); err != nil {
			return errors.New("invalid host callback result")
		}
	}
	return nil
}

func main() {}
