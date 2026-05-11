package auth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/sweeney/mqtt-auth/internal/auth"
	"github.com/sweeney/mqtt-auth/internal/auth/testutil"
)

// Abuse / negative tests beyond what verifier_test.go covers. These probe
// edge cases an attacker might try: NBF in the future, malformed JWKS
// responses, duplicate kids, oversized tokens, audience-shaped claims.

func TestVerifier_rejectsTokenWithNbfInFuture(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	v, _ := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{Issuer: id.Issuer, JWKSURL: id.JWKSURL()})

	tok := id.MintCustom(t, jwt.MapClaims{
		"iss": id.Issuer,
		"sub": "u-1",
		"usr": "alice",
		"iat": time.Now().Add(-time.Minute).Unix(),
		"nbf": time.Now().Add(time.Hour).Unix(),
		"exp": time.Now().Add(2 * time.Hour).Unix(),
	}, nil)

	_, err := v.Parse(context.Background(), tok)
	if !errors.Is(err, auth.ErrTokenInvalid) {
		t.Errorf("nbf-in-future accepted: err = %v", err)
	}
}

func TestVerifier_rejectsTokenWithoutExpClaim(t *testing.T) {
	// We pass WithExpirationRequired to the parser. A token without exp
	// must be rejected, even if everything else is valid.
	id := testutil.NewTestIdentity(t)
	v, _ := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{Issuer: id.Issuer, JWKSURL: id.JWKSURL()})

	tok := id.MintCustom(t, jwt.MapClaims{
		"iss": id.Issuer,
		"sub": "u-1",
		"usr": "alice",
		"iat": time.Now().Unix(),
		// no exp
	}, nil)

	_, err := v.Parse(context.Background(), tok)
	if !errors.Is(err, auth.ErrTokenInvalid) {
		t.Errorf("token without exp accepted: err = %v", err)
	}
}

func TestVerifier_acceptsTokenWithAudienceAsArray(t *testing.T) {
	// Audience can be a single string or an array of strings (RFC 7519
	// §4.1.3). We don't enforce audience in v1 but the claim must be
	// preserved correctly in both shapes.
	id := testutil.NewTestIdentity(t)
	v, _ := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{Issuer: id.Issuer, JWKSURL: id.JWKSURL()})

	tok := id.MintCustom(t, jwt.MapClaims{
		"iss": id.Issuer,
		"sub": "u-1",
		"usr": "alice",
		"aud": []string{"mqtt", "other"},
		"exp": time.Now().Add(time.Hour).Unix(),
	}, nil)

	claims, err := v.Parse(context.Background(), tok)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(claims.Audience) != 2 || claims.Audience[0] != "mqtt" || claims.Audience[1] != "other" {
		t.Errorf("audience array not preserved: %v", claims.Audience)
	}
}

func TestVerifier_skipsMalformedJWKSEntriesAndUsesGoodKey(t *testing.T) {
	// JWKS returned by a real-world identity may include keys we don't
	// support (e.g. RSA), or entries with missing fields. We must skip
	// the bad ones and still verify against the good one rather than
	// failing the whole fetch.

	good, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	goodKID := kidFor(t, &good.PublicKey)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		set := map[string]any{
			"keys": []map[string]any{
				// Missing kid — must be skipped.
				{"kty": "EC", "crv": "P-256", "x": "AAAA", "y": "AAAA"},
				// Wrong curve — must be skipped.
				{"kty": "EC", "crv": "P-384", "kid": "wrong-curve", "x": "AAAA", "y": "AAAA"},
				// RSA — must be skipped.
				{"kty": "RSA", "kid": "rsa", "n": "AAAA", "e": "AQAB"},
				// Bad base64 — must be skipped without breaking the loop.
				{"kty": "EC", "crv": "P-256", "kid": "bad-b64", "x": "@@@", "y": "@@@"},
				// The good one.
				goodJWK(goodKID, good.PublicKey),
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	v, err := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{
		Issuer:  srv.URL,
		JWKSURL: srv.URL + "/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}

	// Mint a token signed by the good key.
	claims := jwt.MapClaims{
		"iss": srv.URL,
		"sub": "u-1",
		"usr": "alice",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = goodKID
	signed, err := tok.SignedString(good)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	c, err := v.Parse(context.Background(), signed)
	if err != nil {
		t.Fatalf("Parse: %v (the good key should still verify despite siblings)", err)
	}
	if c.Username != "alice" {
		t.Errorf("usr = %q", c.Username)
	}
}

func TestVerifier_rejectsWhenJWKSContainsNoUsableKeys(t *testing.T) {
	// If every JWKS entry is junk, refetch must fail loudly rather than
	// silently caching an empty set.
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		set := map[string]any{
			"keys": []map[string]any{
				{"kty": "RSA", "kid": "rsa", "n": "AAAA", "e": "AQAB"},
				{"kty": "oct", "kid": "hmac", "k": "AAAA"},
			},
		}
		_ = json.NewEncoder(w).Encode(set)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	v, _ := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{
		Issuer: srv.URL, JWKSURL: srv.URL + "/.well-known/jwks.json",
	})

	// Any token will trigger the JWKS fetch; it should fail.
	foreign := testutil.GenerateForeignKey(t)
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": srv.URL, "exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = "anything"
	signed, _ := tok.SignedString(foreign)

	_, err := v.Parse(context.Background(), signed)
	if err == nil {
		t.Errorf("expected error when JWKS has no usable keys")
	}
}

func TestVerifier_handlesAbsurdlyLongInput(t *testing.T) {
	// Padding the JWT to several MB should not allocate unboundedly or
	// hang — it should just fail parsing.
	id := testutil.NewTestIdentity(t)
	v, _ := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{Issuer: id.Issuer, JWKSURL: id.JWKSURL()})

	huge := strings.Repeat("a", 5*1024*1024) // 5 MiB
	done := make(chan struct{})
	go func() {
		_, _ = v.Parse(context.Background(), huge)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("Parse hung on 5 MiB input")
	}
}

func TestVerifier_concurrentMixedKIDsShareOneFetch(t *testing.T) {
	// Multiple goroutines parsing tokens with the SAME kid should share a
	// single JWKS fetch via singleflight. Different kids in flight
	// concurrently — after a rotation, say — should still result in just
	// one outbound fetch because the JWKS document is a single resource.
	id := testutil.NewTestIdentity(t)
	id.SetJWKSDelay(50 * time.Millisecond)

	tokOld := id.MintUserToken(t, testutil.UserClaims{Subject: "u-old", Username: "alice"})
	id.RotateKey(t)
	tokNew := id.MintUserToken(t, testutil.UserClaims{Subject: "u-new", Username: "bob"})

	v, _ := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{
		Issuer: id.Issuer, JWKSURL: id.JWKSURL(),
	})

	const N = 20
	var wg sync.WaitGroup
	wg.Add(N * 2)
	for i := 0; i < N; i++ {
		go func() { defer wg.Done(); _, _ = v.Parse(context.Background(), tokOld) }()
		go func() { defer wg.Done(); _, _ = v.Parse(context.Background(), tokNew) }()
	}
	wg.Wait()

	// At most a couple of fetches: one for the initial cold cache, plus
	// possibly one more if a mixed batch raced. The whole point of the
	// singleflight key being constant ("jwks") is that 40 concurrent
	// parses don't fan out to 40 requests.
	if hits := id.JWKSHits(); hits > 2 {
		t.Errorf("JWKS hits = %d under 40 concurrent mixed-kid parses; expected ≤ 2", hits)
	}
}

func TestVerifier_throttlesUnknownKidRefetches(t *testing.T) {
	// A burst of bad tokens (all referencing an unknown kid) must not
	// hammer the identity service. The refetch_min throttle should kick
	// in after the first miss.
	id := testutil.NewTestIdentity(t)
	v, _ := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{
		Issuer:             id.Issuer,
		JWKSURL:            id.JWKSURL(),
		CacheTTL:           time.Hour,
		RefetchMinInterval: time.Hour, // anything past first miss is throttled
	})

	// Warm the cache with a valid parse.
	good := id.MintUserToken(t, testutil.UserClaims{Subject: "u", Username: "alice"})
	if _, err := v.Parse(context.Background(), good); err != nil {
		t.Fatalf("warm-up: %v", err)
	}
	warmHits := id.JWKSHits()

	// Now blast bad-kid tokens.
	foreign := testutil.GenerateForeignKey(t)
	for i := 0; i < 50; i++ {
		bad := id.MintWithKey(t, foreign, "rogue-kid", jwt.MapClaims{
			"iss": id.Issuer, "exp": time.Now().Add(time.Hour).Unix(),
		}, nil)
		_, _ = v.Parse(context.Background(), bad)
	}

	// At most one refetch (the first kid miss), then throttled.
	delta := id.JWKSHits() - warmHits
	if delta > 1 {
		t.Errorf("unknown-kid refetches not throttled: %d extra hits", delta)
	}
}

// goodJWK and kidFor mirror the on-wire shape testutil uses but are inlined
// here so this file can build a custom JWKS with deliberately-bad siblings.
func goodJWK(kid string, pub ecdsa.PublicKey) map[string]any {
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	x := padLeft(pub.X.Bytes(), byteLen)
	y := padLeft(pub.Y.Bytes(), byteLen)
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"kid": kid,
		"alg": "ES256",
		"use": "sig",
		"x":   base64.RawURLEncoding.EncodeToString(x),
		"y":   base64.RawURLEncoding.EncodeToString(y),
	}
}

func kidFor(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

func padLeft(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}
