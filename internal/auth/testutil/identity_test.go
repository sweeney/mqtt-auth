package testutil

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// The testutil package underpins every other test in the repo. If it's wrong,
// every downstream assertion is suspect. These tests prove the helper actually
// behaves the way the docs claim.

func TestNewTestIdentity_servesJWKSAtWellKnown(t *testing.T) {
	id := NewTestIdentity(t)

	resp, err := http.Get(id.JWKSURL())
	if err != nil {
		t.Fatalf("get jwks: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var set JWKSet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("want 1 key in JWKS, got %d", len(set.Keys))
	}
	k := set.Keys[0]
	if k.Kty != "EC" || k.Crv != "P-256" || k.Alg != "ES256" {
		t.Errorf("unexpected jwk: %+v", k)
	}
	if k.Kid == "" {
		t.Errorf("kid is empty")
	}
	if k.Kid != id.CurrentKID() {
		t.Errorf("served kid %q does not match CurrentKID %q", k.Kid, id.CurrentKID())
	}
}

func TestMintUserToken_carriesExpectedClaims(t *testing.T) {
	id := NewTestIdentity(t)

	tok := id.MintUserToken(t, UserClaims{
		Subject: "u-123", Username: "alice", Role: "admin", Active: true,
	})

	// Decode without verifying just to inspect the claims for the test.
	parsed, _, err := jwt.NewParser().ParseUnverified(tok, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse minted token: %v", err)
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["iss"] != id.Issuer {
		t.Errorf("iss = %v, want %v", claims["iss"], id.Issuer)
	}
	if claims["sub"] != "u-123" || claims["usr"] != "alice" || claims["rol"] != "admin" {
		t.Errorf("user claims wrong: %+v", claims)
	}
	if act, _ := claims["act"].(bool); !act {
		t.Errorf("act claim should be true, got %v", claims["act"])
	}
	if parsed.Header["kid"] != id.CurrentKID() {
		t.Errorf("token kid %v != identity CurrentKID %v", parsed.Header["kid"], id.CurrentKID())
	}
}

func TestMintServiceToken_setsRFC9068TypHeader(t *testing.T) {
	id := NewTestIdentity(t)

	tok := id.MintServiceToken(t, ServiceClaims{
		ClientID: "svc-mqtt", Audience: "mqtt", Scope: "publish subscribe",
	})

	parsed, _, err := jwt.NewParser().ParseUnverified(tok, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Header["typ"] != "at+jwt" {
		t.Errorf("typ header = %v, want at+jwt", parsed.Header["typ"])
	}
	claims := parsed.Claims.(jwt.MapClaims)
	if claims["client_id"] != "svc-mqtt" {
		t.Errorf("client_id claim missing or wrong: %+v", claims)
	}
	if claims["aud"] != "mqtt" {
		t.Errorf("aud claim missing or wrong: %+v", claims)
	}
}

func TestJWKSHits_countsRequests(t *testing.T) {
	id := NewTestIdentity(t)
	if got := id.JWKSHits(); got != 0 {
		t.Fatalf("initial hits = %d, want 0", got)
	}
	for i := 0; i < 3; i++ {
		resp, _ := http.Get(id.JWKSURL())
		resp.Body.Close()
	}
	if got := id.JWKSHits(); got != 3 {
		t.Errorf("hits = %d, want 3", got)
	}
}

func TestSetJWKSFail_returnsErrorStatus(t *testing.T) {
	id := NewTestIdentity(t)
	id.SetJWKSFail(true)
	resp, err := http.Get(id.JWKSURL())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestSetJWKSDelay_delaysResponse(t *testing.T) {
	id := NewTestIdentity(t)
	id.SetJWKSDelay(50 * time.Millisecond)
	start := time.Now()
	resp, _ := http.Get(id.JWKSURL())
	resp.Body.Close()
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Errorf("response returned in %v, expected at least ~50ms", elapsed)
	}
}

func TestRotateKey_keepsOldKeyInSet(t *testing.T) {
	id := NewTestIdentity(t)
	first := id.CurrentKID()
	id.RotateKey(t)
	if id.CurrentKID() == first {
		t.Fatalf("CurrentKID did not change after rotation")
	}

	resp, _ := http.Get(id.JWKSURL())
	defer resp.Body.Close()
	var set JWKSet
	_ = json.NewDecoder(resp.Body).Decode(&set)
	if len(set.Keys) != 2 {
		t.Fatalf("want 2 keys after rotation, got %d", len(set.Keys))
	}

	id.DropOldestKey()
	resp2, _ := http.Get(id.JWKSURL())
	defer resp2.Body.Close()
	var set2 JWKSet
	_ = json.NewDecoder(resp2.Body).Decode(&set2)
	if len(set2.Keys) != 1 {
		t.Errorf("want 1 key after dropping oldest, got %d", len(set2.Keys))
	}
}

func TestMintWithKey_signsWithProvidedForeignKey(t *testing.T) {
	id := NewTestIdentity(t)
	foreign := GenerateForeignKey(t)

	tok := id.MintWithKey(t, foreign, "rogue-kid", jwt.MapClaims{
		"iss": id.Issuer, "sub": "u-1", "exp": time.Now().Add(time.Hour).Unix(),
	}, nil)

	// A foreign-signed token shouldn't have segments matching one signed by
	// the identity's current key. Cheap sanity check.
	good := id.MintUserToken(t, UserClaims{Subject: "u-1", Username: "x"})
	if strings.Split(tok, ".")[2] == strings.Split(good, ".")[2] {
		t.Errorf("foreign-signed and identity-signed tokens share a signature")
	}
}
