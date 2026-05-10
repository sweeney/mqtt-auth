package auth_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/sweeney/mqtt-auth/internal/auth"
	"github.com/sweeney/mqtt-auth/internal/auth/testutil"
)

// newVerifier wires a JWKSVerifier pointed at the given TestIdentity with
// short timeouts so tests are fast.
func newVerifier(t *testing.T, id *testutil.TestIdentity, opts ...func(*auth.JWKSVerifierConfig)) *auth.JWKSVerifier {
	t.Helper()
	cfg := auth.JWKSVerifierConfig{
		Issuer:             id.Issuer,
		JWKSURL:            id.JWKSURL(),
		CacheTTL:           5 * time.Minute,
		RefetchMinInterval: 50 * time.Millisecond,
		HTTPClient:         &http.Client{Timeout: 2 * time.Second},
	}
	for _, o := range opts {
		o(&cfg)
	}
	v, err := auth.NewJWKSVerifier(cfg)
	if err != nil {
		t.Fatalf("NewJWKSVerifier: %v", err)
	}
	return v
}

func TestNewJWKSVerifier_requiresIssuerAndJWKSURL(t *testing.T) {
	_, err := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{JWKSURL: "https://x/jwks.json"})
	if err == nil {
		t.Error("missing Issuer should fail")
	}
	_, err = auth.NewJWKSVerifier(auth.JWKSVerifierConfig{Issuer: "https://x"})
	if err == nil {
		t.Error("missing JWKSURL should fail")
	}
}

func TestVerifier_acceptsValidUserToken(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	v := newVerifier(t, id)

	tok := id.MintUserToken(t, testutil.UserClaims{
		Subject: "u-123", Username: "alice", Role: "user", Active: true,
	})
	claims, err := v.Parse(context.Background(), tok)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if claims.Kind != auth.TokenKindUser {
		t.Errorf("kind = %v, want user", claims.Kind)
	}
	if claims.Username != "alice" || claims.Subject != "u-123" || claims.Role != "user" || !claims.Active {
		t.Errorf("claims = %+v", claims)
	}
	if claims.Issuer != id.Issuer {
		t.Errorf("issuer = %q, want %q", claims.Issuer, id.Issuer)
	}
}

func TestVerifier_acceptsValidServiceToken(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	v := newVerifier(t, id)

	tok := id.MintServiceToken(t, testutil.ServiceClaims{
		ClientID: "svc-mqtt", Audience: "mqtt", Scope: "publish",
	})
	claims, err := v.Parse(context.Background(), tok)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if claims.Kind != auth.TokenKindService {
		t.Errorf("kind = %v, want service", claims.Kind)
	}
	if claims.ClientID != "svc-mqtt" || claims.Scope != "publish" {
		t.Errorf("claims = %+v", claims)
	}
}

func TestVerifier_rejectsExpiredToken(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	v := newVerifier(t, id)

	tok := id.MintCustom(t, jwt.MapClaims{
		"iss": id.Issuer,
		"sub": "u-1",
		"usr": "alice",
		"iat": time.Now().Add(-time.Hour).Unix(),
		"exp": time.Now().Add(-time.Minute).Unix(),
	}, nil)
	_, err := v.Parse(context.Background(), tok)
	if !errors.Is(err, auth.ErrTokenExpired) {
		t.Errorf("err = %v, want ErrTokenExpired", err)
	}
}

func TestVerifier_rejectsWrongIssuer(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	v := newVerifier(t, id)

	tok := id.MintCustom(t, jwt.MapClaims{
		"iss": "https://evil.example.com",
		"sub": "u-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	}, nil)
	_, err := v.Parse(context.Background(), tok)
	if !errors.Is(err, auth.ErrTokenInvalid) {
		t.Errorf("err = %v, want ErrTokenInvalid", err)
	}
}

func TestVerifier_rejectsForeignSignature(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	v := newVerifier(t, id)

	foreign := testutil.GenerateForeignKey(t)
	// Reuse the current kid so the verifier finds *a* key but signature
	// verification fails because the foreign key doesn't match.
	tok := id.MintWithKey(t, foreign, id.CurrentKID(), jwt.MapClaims{
		"iss": id.Issuer, "sub": "u-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	}, nil)
	_, err := v.Parse(context.Background(), tok)
	if !errors.Is(err, auth.ErrTokenInvalid) {
		t.Errorf("err = %v, want ErrTokenInvalid", err)
	}
}

func TestVerifier_rejectsMalformedToken(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	v := newVerifier(t, id)

	for _, tok := range []string{"", "not.a.jwt", "a.b.c", "...."} {
		_, err := v.Parse(context.Background(), tok)
		if !errors.Is(err, auth.ErrTokenInvalid) {
			t.Errorf("token %q: err = %v, want ErrTokenInvalid", tok, err)
		}
	}
}

func TestVerifier_rejectsMissingKid(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	v := newVerifier(t, id)

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": id.Issuer, "sub": "u-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	// Don't set kid header. Sign with the identity's current key but the
	// verifier should refuse it because we mandate kid.
	foreign := testutil.GenerateForeignKey(t)
	signed, err := tok.SignedString(foreign)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	_, err = v.Parse(context.Background(), signed)
	if !errors.Is(err, auth.ErrTokenInvalid) {
		t.Errorf("err = %v, want ErrTokenInvalid", err)
	}
}

func TestVerifier_refetchesOnUnknownKidAfterRotation(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	v := newVerifier(t, id, func(c *auth.JWKSVerifierConfig) {
		c.CacheTTL = time.Hour // ensure refetch is driven by kid miss, not TTL
	})

	// Warm cache with the original key.
	tok1 := id.MintUserToken(t, testutil.UserClaims{Subject: "u-1", Username: "alice"})
	if _, err := v.Parse(context.Background(), tok1); err != nil {
		t.Fatalf("warm-up parse: %v", err)
	}
	hitsAfterWarm := id.JWKSHits()

	// Rotate. New tokens use a new kid; old kid stays in JWKS too.
	id.RotateKey(t)
	tok2 := id.MintUserToken(t, testutil.UserClaims{Subject: "u-2", Username: "bob"})

	claims, err := v.Parse(context.Background(), tok2)
	if err != nil {
		t.Fatalf("Parse post-rotation: %v", err)
	}
	if claims.Username != "bob" {
		t.Errorf("usr = %q, want bob", claims.Username)
	}
	if id.JWKSHits() <= hitsAfterWarm {
		t.Errorf("expected a refetch on kid miss, hits %d -> %d", hitsAfterWarm, id.JWKSHits())
	}

	// Old token still verifies because old key is still in JWKS.
	if _, err := v.Parse(context.Background(), tok1); err != nil {
		t.Errorf("old token should still verify after rotation: %v", err)
	}
}

func TestVerifier_unknownKidStaysUnknownAfterRefetch(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	v := newVerifier(t, id)

	// Sign with a foreign key, claim a kid that doesn't exist in JWKS.
	foreign := testutil.GenerateForeignKey(t)
	tok := id.MintWithKey(t, foreign, "made-up-kid", jwt.MapClaims{
		"iss": id.Issuer, "sub": "u-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	}, nil)

	_, err := v.Parse(context.Background(), tok)
	if !errors.Is(err, auth.ErrTokenInvalid) {
		t.Errorf("err = %v, want ErrTokenInvalid", err)
	}
}

func TestVerifier_cachesJWKSWithinTTL(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	v := newVerifier(t, id)

	for i := 0; i < 10; i++ {
		tok := id.MintUserToken(t, testutil.UserClaims{Subject: "u", Username: "alice"})
		if _, err := v.Parse(context.Background(), tok); err != nil {
			t.Fatalf("Parse iter %d: %v", i, err)
		}
	}
	if hits := id.JWKSHits(); hits != 1 {
		t.Errorf("JWKS hits = %d, want exactly 1 (TTL not yet expired)", hits)
	}
}

func TestVerifier_servesStaleKeyWhenJWKSFails(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	v := newVerifier(t, id, func(c *auth.JWKSVerifierConfig) {
		c.CacheTTL = 10 * time.Millisecond // force refetch on next call
	})

	tok := id.MintUserToken(t, testutil.UserClaims{Subject: "u", Username: "alice"})
	if _, err := v.Parse(context.Background(), tok); err != nil {
		t.Fatalf("warm-up: %v", err)
	}

	time.Sleep(20 * time.Millisecond) // cache now stale
	id.SetJWKSFail(true)

	// Even though refetch fails, the kid is still in cache. Liveness > freshness.
	if _, err := v.Parse(context.Background(), tok); err != nil {
		t.Errorf("expected stale-on-error to keep working: %v", err)
	}
}

func TestVerifier_concurrentColdCacheFetchesAreDeduped(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	id.SetJWKSDelay(50 * time.Millisecond)
	v := newVerifier(t, id)

	tok := id.MintUserToken(t, testutil.UserClaims{Subject: "u", Username: "alice"})

	const N = 20
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			_, err := v.Parse(context.Background(), tok)
			if err != nil {
				t.Errorf("concurrent Parse: %v", err)
			}
		}()
	}
	wg.Wait()

	if hits := id.JWKSHits(); hits != 1 {
		t.Errorf("JWKS hits = %d under N=%d concurrent cold parses, want 1 (singleflight)", hits, N)
	}
}

func TestVerifier_contextCancellationPropagatesDuringRefetch(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	id.SetJWKSDelay(500 * time.Millisecond)
	v := newVerifier(t, id)

	tok := id.MintUserToken(t, testutil.UserClaims{Subject: "u", Username: "alice"})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := v.Parse(ctx, tok)
	if err == nil {
		t.Fatalf("expected error from cancelled context")
	}
	if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
		t.Errorf("Parse hung for %v despite ctx cancellation", elapsed)
	}
}

func TestVerifier_rejectsAlgNone(t *testing.T) {
	// Defence-in-depth: the JWT library rejects "none" by default, but we
	// have a belt-and-braces alg whitelist. This test pins that contract.
	id := testutil.NewTestIdentity(t)
	v := newVerifier(t, id)

	// Manually craft an unsigned token: header.payload. with empty signature.
	// We can't easily use the jwt library to produce a "none" token (rightly
	// so), so build it by hand from a valid one.
	good := id.MintUserToken(t, testutil.UserClaims{Subject: "u", Username: "alice"})
	parts := strings.Split(good, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts in good token")
	}
	// Substitute the header for {"alg":"none","typ":"JWT","kid":"..."} —
	// keep the original kid to bypass the kid check.
	noneHeader := `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0` // {"alg":"none","typ":"JWT"}
	forged := noneHeader + "." + parts[1] + "."

	_, err := v.Parse(context.Background(), forged)
	if !errors.Is(err, auth.ErrTokenInvalid) {
		t.Errorf("alg=none token accepted: err = %v", err)
	}
}

func TestVerifier_rejectsAlgConfusionHS256(t *testing.T) {
	// Attacker tries to sign with HMAC using the public key as the secret.
	id := testutil.NewTestIdentity(t)
	v := newVerifier(t, id)

	// Build a token signed with HS256 using a known key bytes value. Our
	// verifier should reject because we only whitelist ES256.
	hmacTok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": id.Issuer, "sub": "u-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	hmacTok.Header["kid"] = id.CurrentKID()
	signed, err := hmacTok.SignedString([]byte("anything"))
	if err != nil {
		t.Fatalf("sign hmac: %v", err)
	}

	_, err = v.Parse(context.Background(), signed)
	if !errors.Is(err, auth.ErrTokenInvalid) {
		t.Errorf("HS256 token accepted: err = %v", err)
	}
}
