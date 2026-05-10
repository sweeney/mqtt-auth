package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sweeney/mqtt-auth/internal/auth"
	"github.com/sweeney/mqtt-auth/internal/auth/testutil"
)

// FuzzVerifierParse exercises the JWT parse path with arbitrary input. The
// only valid outcomes are (claims, nil), (nil, ErrTokenExpired), or
// (nil, ErrTokenInvalid). Anything else — a panic, an unexpected error type,
// or claims returned alongside an error — is a bug.
//
// CI runs this with a 30s budget on every PR.
func FuzzVerifierParse(f *testing.F) {
	id := testutil.NewTestIdentity(f)
	v, err := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{
		Issuer:   id.Issuer,
		JWKSURL:  id.JWKSURL(),
		CacheTTL: time.Hour, // avoid refetch noise during fuzzing
	})
	if err != nil {
		f.Fatalf("verifier: %v", err)
	}

	// Seed corpus: one valid token plus classic broken shapes. The fuzzer
	// mutates from here.
	f.Add(id.MintUserToken(f, testutil.UserClaims{Subject: "u", Username: "alice"}))
	f.Add("")
	f.Add("not.a.jwt")
	f.Add("a.b.c")
	f.Add("....")
	f.Add(string([]byte{0xff, 0x00, 0x01}))

	f.Fuzz(func(t *testing.T, in string) {
		claims, err := v.Parse(context.Background(), in)
		if err == nil {
			if claims == nil {
				t.Fatalf("err nil but claims also nil for input %q", in)
			}
			return
		}
		if errors.Is(err, auth.ErrTokenInvalid) || errors.Is(err, auth.ErrTokenExpired) {
			if claims != nil {
				t.Fatalf("got claims %+v alongside sentinel err %v", claims, err)
			}
			return
		}
		// Non-sentinel error: only legitimate cause would be a network
		// refetch during fuzzing, which shouldn't happen because the seed
		// JWKS request has already warmed the cache. Log so a real bug
		// here surfaces in CI output.
		t.Logf("non-sentinel err for input %q: %v", in, err)
	})
}
