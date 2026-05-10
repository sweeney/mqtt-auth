// Package main is the cgo entry point for the mosquitto auth plugin. It is
// built as a c-shared library (`go build -buildmode=c-shared`) that
// mosquitto loads at startup.
//
// All real logic lives in internal/runtime; this file is a thin translation
// layer between C strings and Go.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"unsafe"

	"github.com/sweeney/mqtt-auth/internal/runtime"
)

// AuthPluginInit is called from mosquitto_auth_plugin_init. The C side
// flattens the struct mosquitto_opt array into parallel C string arrays so
// cgo conversion is simpler.
//
//export AuthPluginInit
func AuthPluginInit(keysPtr **C.char, valuesPtr **C.char, count C.int) C.int {
	n := int(count)
	keys := make([]string, n)
	values := make([]string, n)
	if n > 0 {
		keySlice := unsafe.Slice(keysPtr, n)
		valSlice := unsafe.Slice(valuesPtr, n)
		for i := 0; i < n; i++ {
			keys[i] = C.GoString(keySlice[i])
			values[i] = C.GoString(valSlice[i])
		}
	}
	opts, err := runtime.OptsToMap(keys, values)
	if err != nil {
		return C.int(runtime.MosqErrInval)
	}
	return C.int(runtime.Init(opts))
}

// AuthPluginCleanup is called from mosquitto_auth_plugin_cleanup.
//
//export AuthPluginCleanup
func AuthPluginCleanup() {
	runtime.Cleanup()
}

// AuthUnpwdCheck is called from mosquitto_auth_unpwd_check. mosquitto passes
// NULL for missing username/password — C.GoString handles that as "".
//
//export AuthUnpwdCheck
func AuthUnpwdCheck(username, password *C.char) C.int {
	return C.int(runtime.Authenticate(context.Background(), C.GoString(username), C.GoString(password)))
}

// AuthAclCheck is called from mosquitto_auth_acl_check. v1: allow.
//
//export AuthAclCheck
func AuthAclCheck(username, topic *C.char, access C.int) C.int {
	return C.int(runtime.CheckACL(C.GoString(username), C.GoString(topic), int(access)))
}

func main() {}
