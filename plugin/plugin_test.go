//go:build mqttauth_plugintest

// Tests for the cgo translation layer. The runtime logic lives in
// internal/runtime; these tests exercise plugin.go's //export functions
// on their actual cgo signatures, focusing on what only this layer can
// get wrong: NULL pointers, opt-array flattening, init/cleanup ordering.
//
// Requires libmosquitto/mosquitto plugin headers and a test build tag —
// run via `go test -tags=mqttauth_plugintest ./plugin/...`.

package main

import (
	"testing"

	"github.com/sweeney/mqtt-auth/internal/auth/testutil"
	"github.com/sweeney/mqtt-auth/internal/runtime"
)

func TestAuthPluginInit_emptyOpts_failsWithInval(t *testing.T) {
	defer runtime.Cleanup()
	if rc := callAuthPluginInit(nil); rc != runtime.MosqErrInval {
		t.Errorf("AuthPluginInit(nil, nil, 0) = %d, want MOSQ_ERR_INVAL (%d) since jwt_issuer is missing",
			rc, runtime.MosqErrInval)
	}
}

func TestAuthPluginInit_validOpts_succeeds(t *testing.T) {
	defer runtime.Cleanup()
	id := testutil.NewTestIdentity(t)

	rc := callAuthPluginInit(map[string]string{
		"jwt_issuer":   id.Issuer,
		"jwt_jwks_url": id.JWKSURL(),
	})
	if rc != runtime.MosqErrSuccess {
		t.Errorf("AuthPluginInit = %d, want SUCCESS", rc)
	}
}

func TestAuthPluginInit_unknownOpt_failsWithInval(t *testing.T) {
	defer runtime.Cleanup()
	rc := callAuthPluginInit(map[string]string{
		"jwt_issuer":  "https://id.swee.net",
		"jwt_typo_x": "value",
	})
	if rc != runtime.MosqErrInval {
		t.Errorf("AuthPluginInit with typo = %d, want INVAL", rc)
	}
}

func TestAuthUnpwdCheck_nilUsernameAndPassword_returnsAuth(t *testing.T) {
	// mosquitto passes NULL pointers when CONNECT omits username or
	// password. C.GoString(NULL) returns "" — the runtime must treat
	// that as "empty creds, deny".
	defer runtime.Cleanup()
	id := testutil.NewTestIdentity(t)
	mustInit(t, id)

	if rc := callAuthUnpwdCheck("", "", false, false); rc != runtime.MosqErrAuth {
		t.Errorf("AuthUnpwdCheck(NULL, NULL) = %d, want AUTH (empty creds must be denied)", rc)
	}
}

func TestAuthUnpwdCheck_nilPassword_returnsAuth(t *testing.T) {
	defer runtime.Cleanup()
	id := testutil.NewTestIdentity(t)
	mustInit(t, id)

	if rc := callAuthUnpwdCheck("alice", "", true, false); rc != runtime.MosqErrAuth {
		t.Errorf("AuthUnpwdCheck(alice, NULL) = %d, want AUTH", rc)
	}
}

func TestAuthUnpwdCheck_nilUsernameWithValidToken_returnsAuth(t *testing.T) {
	// Username binding is on by default; an empty MQTT username can't
	// match the token's principal.
	defer runtime.Cleanup()
	id := testutil.NewTestIdentity(t)
	mustInit(t, id)

	tok := id.MintUserToken(t, testutil.UserClaims{Subject: "u", Username: "alice"})
	if rc := callAuthUnpwdCheck("", tok, false, true); rc != runtime.MosqErrAuth {
		t.Errorf("AuthUnpwdCheck(NULL user, valid tok) = %d, want AUTH", rc)
	}
}

func TestAuthUnpwdCheck_validToken_returnsSuccess(t *testing.T) {
	defer runtime.Cleanup()
	id := testutil.NewTestIdentity(t)
	mustInit(t, id)

	tok := id.MintUserToken(t, testutil.UserClaims{Subject: "u-1", Username: "alice"})
	if rc := callAuthUnpwdCheck("alice", tok, true, true); rc != runtime.MosqErrSuccess {
		t.Errorf("AuthUnpwdCheck(alice, validJWT) = %d, want SUCCESS", rc)
	}
}

func TestAuthUnpwdCheck_wrongUsername_returnsAuth(t *testing.T) {
	defer runtime.Cleanup()
	id := testutil.NewTestIdentity(t)
	mustInit(t, id)

	tok := id.MintUserToken(t, testutil.UserClaims{Subject: "u-1", Username: "alice"})
	if rc := callAuthUnpwdCheck("mallory", tok, true, true); rc != runtime.MosqErrAuth {
		t.Errorf("AuthUnpwdCheck(mallory, alice's token) = %d, want AUTH", rc)
	}
}

func TestAuthUnpwdCheck_beforeInit_returnsUnknown(t *testing.T) {
	runtime.Cleanup() // clear any leftover state from prior tests
	if rc := callAuthUnpwdCheck("alice", "anything", true, true); rc != runtime.MosqErrUnknown {
		t.Errorf("AuthUnpwdCheck before Init = %d, want UNKNOWN (plumbing failure)", rc)
	}
}

func TestAuthPluginCleanup_clearsRuntime(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	mustInit(t, id)

	callAuthPluginCleanup()

	tok := id.MintUserToken(t, testutil.UserClaims{Subject: "u", Username: "alice"})
	if rc := callAuthUnpwdCheck("alice", tok, true, true); rc != runtime.MosqErrUnknown {
		t.Errorf("AuthUnpwdCheck after Cleanup = %d, want UNKNOWN", rc)
	}
}

func TestAuthPluginInit_reinit_replacesRuntime(t *testing.T) {
	// Two successive Inits (e.g. via security_init(reload=true)) should
	// not leak the old runtime — the second Init replaces it cleanly.
	defer runtime.Cleanup()
	id1 := testutil.NewTestIdentity(t)
	mustInit(t, id1)

	id2 := testutil.NewTestIdentity(t)
	mustInit(t, id2)

	tok2 := id2.MintUserToken(t, testutil.UserClaims{Subject: "u", Username: "alice"})
	if rc := callAuthUnpwdCheck("alice", tok2, true, true); rc != runtime.MosqErrSuccess {
		t.Errorf("token from new issuer = %d, want SUCCESS", rc)
	}

	tok1 := id1.MintUserToken(t, testutil.UserClaims{Subject: "u", Username: "alice"})
	if rc := callAuthUnpwdCheck("alice", tok1, true, true); rc != runtime.MosqErrAuth {
		t.Errorf("token from previous issuer = %d, want AUTH (issuer mismatch)", rc)
	}
}

func TestAuthAclCheck_v1_alwaysAllows(t *testing.T) {
	// v1 ACL is allow-all. The MQTT_AUTH_TESTING stub for
	// plugin_client_username returns NULL, so AuthAclCheck receives a
	// NULL username pointer (C.GoString(NULL) is "") and still returns
	// SUCCESS.
	if rc := callAuthAclCheck("anything/#", 1); rc != runtime.MosqErrSuccess {
		t.Errorf("AuthAclCheck = %d, want SUCCESS (v1 allow-all)", rc)
	}
}

func mustInit(t *testing.T, id *testutil.TestIdentity) {
	t.Helper()
	rc := callAuthPluginInit(map[string]string{
		"jwt_issuer":   id.Issuer,
		"jwt_jwks_url": id.JWKSURL(),
	})
	if rc != runtime.MosqErrSuccess {
		t.Fatalf("AuthPluginInit failed: %d", rc)
	}
}
