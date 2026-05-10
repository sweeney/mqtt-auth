package runtime

import (
	"context"
	"testing"

	"github.com/sweeney/mqtt-auth/internal/auth/testutil"
)

// These tests cover the runtime entrypoints that the cgo layer calls into.
// The cgo glue itself is exercised by the end-to-end suite; here we prove
// the Go-side state machine and translation logic.

func TestInit_failsWithoutIssuer(t *testing.T) {
	defer Cleanup()
	if got := Init(map[string]string{}); got != MosqErrInval {
		t.Errorf("init without issuer = %d, want MOSQ_ERR_INVAL (%d)", got, MosqErrInval)
	}
	if state.Load() != nil {
		t.Error("state should not be set after failed init")
	}
}

func TestInit_failsOnUnknownOption(t *testing.T) {
	defer Cleanup()
	got := Init(map[string]string{
		"jwt_issuer": "https://id.swee.net",
		"jwt_typo_x": "value",
	})
	if got != MosqErrInval {
		t.Errorf("init with typo = %d, want MOSQ_ERR_INVAL", got)
	}
}

func TestInit_succeedsWithMinimalConfig(t *testing.T) {
	defer Cleanup()
	got := Init(map[string]string{"jwt_issuer": "https://id.swee.net"})
	if got != MosqErrSuccess {
		t.Errorf("init = %d, want SUCCESS", got)
	}
	if state.Load() == nil {
		t.Error("state should be set after successful init")
	}
}

func TestAuthenticate_nilStateReturnsUnknown(t *testing.T) {
	Cleanup() // ensure nil
	if got := Authenticate(context.Background(), "alice", "tok"); got != MosqErrUnknown {
		t.Errorf("Authenticate with nil state = %d, want UNKNOWN", got)
	}
}

func TestAuthenticate_validTokenReturnsSuccess(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	defer Cleanup()
	if got := Init(map[string]string{"jwt_issuer": id.Issuer, "jwt_jwks_url": id.JWKSURL()}); got != MosqErrSuccess {
		t.Fatalf("init: %d", got)
	}

	tok := id.MintUserToken(t, testutil.UserClaims{Subject: "u", Username: "alice"})
	if got := Authenticate(context.Background(), "alice", tok); got != MosqErrSuccess {
		t.Errorf("Authenticate valid = %d, want SUCCESS", got)
	}
}

func TestAuthenticate_invalidTokenReturnsAuth(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	defer Cleanup()
	Init(map[string]string{"jwt_issuer": id.Issuer, "jwt_jwks_url": id.JWKSURL()})

	if got := Authenticate(context.Background(), "alice", "garbage"); got != MosqErrAuth {
		t.Errorf("Authenticate garbage = %d, want AUTH", got)
	}
}

func TestAuthenticate_usernameMismatchReturnsAuth(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	defer Cleanup()
	Init(map[string]string{"jwt_issuer": id.Issuer, "jwt_jwks_url": id.JWKSURL()})

	tok := id.MintUserToken(t, testutil.UserClaims{Subject: "u", Username: "alice"})
	if got := Authenticate(context.Background(), "mallory", tok); got != MosqErrAuth {
		t.Errorf("Authenticate mismatched = %d, want AUTH", got)
	}
}

func TestCheckACL_v1AllowsEverything(t *testing.T) {
	if got := CheckACL("alice", "any/topic/#", 1); got != MosqErrSuccess {
		t.Errorf("CheckACL = %d, want SUCCESS (v1 is allow-all)", got)
	}
}

func TestOptsToMap(t *testing.T) {
	m, err := OptsToMap([]string{"a", "b"}, []string{"1", "2"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if m["a"] != "1" || m["b"] != "2" {
		t.Errorf("map: %v", m)
	}
}

func TestOptsToMap_mismatchedLengths(t *testing.T) {
	if _, err := OptsToMap([]string{"a"}, []string{}); err == nil {
		t.Error("expected error on length mismatch")
	}
}
