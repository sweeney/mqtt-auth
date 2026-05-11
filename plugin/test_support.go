//go:build mqttauth_plugintest

// This file is only compiled when the test binary is built via
//   go test -tags=mqttauth_plugintest ./plugin/...
//
// It exists because:
//   1. Go forbids `import "C"` inside *_test.go files, so the test file
//      can't directly construct *C.char values to call AuthUnpwdCheck.
//   2. We need MQTT_AUTH_TESTING defined in test builds to stub the
//      broker-only mosquitto_client_username symbol; defining it in a
//      regular .go file would also affect the production .so build.
//
// Gating both behind the build tag keeps test-only cgo and the testing
// macro out of every other build.

package main

/*
#cgo CFLAGS: -DMQTT_AUTH_TESTING
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"
)

// callAuthPluginInit builds the parallel **C.char arrays mosquitto would
// pass and invokes the cgo entrypoint. nil opts produces a zero-count
// call.
func callAuthPluginInit(opts map[string]string) int {
	if len(opts) == 0 {
		return int(AuthPluginInit(nil, nil, 0))
	}
	n := len(opts)
	keys := make([]*C.char, n)
	vals := make([]*C.char, n)
	i := 0
	for k, v := range opts {
		keys[i] = C.CString(k)
		vals[i] = C.CString(v)
		i++
	}
	defer func() {
		for _, p := range keys {
			C.free(unsafe.Pointer(p))
		}
		for _, p := range vals {
			C.free(unsafe.Pointer(p))
		}
	}()
	return int(AuthPluginInit(&keys[0], &vals[0], C.int(n)))
}

// callAuthUnpwdCheck takes optional username/password; if either pointer
// flag is false the corresponding argument is passed as NULL (matching
// mosquitto's behaviour when CONNECT omits the field).
func callAuthUnpwdCheck(username, password string, hasUser, hasPass bool) int {
	var cu, cp *C.char
	if hasUser {
		cu = C.CString(username)
		defer C.free(unsafe.Pointer(cu))
	}
	if hasPass {
		cp = C.CString(password)
		defer C.free(unsafe.Pointer(cp))
	}
	return int(AuthUnpwdCheck(cu, cp))
}

// callAuthAclCheck invokes AuthAclCheck with a stubbed-NULL username
// (the MQTT_AUTH_TESTING stub returns NULL from plugin_client_username).
func callAuthAclCheck(topic string, access int) int {
	cT := C.CString(topic)
	defer C.free(unsafe.Pointer(cT))
	return int(AuthAclCheck(nil, cT, C.int(access)))
}

// callAuthPluginCleanup is a thin pass-through; lives here so the test
// file doesn't need its own cgo import.
func callAuthPluginCleanup() {
	AuthPluginCleanup()
}
