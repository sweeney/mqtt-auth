package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/sweeney/mqtt-auth/internal/auth"
	"github.com/sweeney/mqtt-auth/internal/auth/testutil"
)

// stubVerifier lets tests focus on the Authenticator's decision logic in
// isolation from real JWT/JWKS handling.
type stubVerifier struct {
	claims *auth.Claims
	err    error
}

func (s *stubVerifier) Parse(_ context.Context, _ string) (*auth.Claims, error) {
	return s.claims, s.err
}

func newAuth(t *testing.T, v auth.Verifier, opts ...func(*auth.AuthenticatorConfig)) *auth.Authenticator {
	t.Helper()
	cfg := auth.AuthenticatorConfig{Verifier: v, RequireUsernameMatch: true}
	for _, o := range opts {
		o(&cfg)
	}
	a, err := auth.NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return a
}

func TestNewAuthenticator_requiresVerifier(t *testing.T) {
	if _, err := auth.NewAuthenticator(auth.AuthenticatorConfig{}); err == nil {
		t.Error("expected error when Verifier is nil")
	}
}

func TestAuthenticator_allowsValidUserTokenWithMatchingUsername(t *testing.T) {
	a := newAuth(t, &stubVerifier{claims: &auth.Claims{
		Kind: auth.TokenKindUser, Subject: "u-1", Username: "alice",
	}})
	ok, err := a.Authenticate(context.Background(), "alice", "tok")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !ok {
		t.Errorf("expected allow")
	}
}

func TestAuthenticator_deniesUserTokenWhenUsernameDiffers(t *testing.T) {
	a := newAuth(t, &stubVerifier{claims: &auth.Claims{
		Kind: auth.TokenKindUser, Subject: "u-1", Username: "alice",
	}})
	ok, err := a.Authenticate(context.Background(), "mallory", "tok")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ok {
		t.Errorf("expected deny when MQTT username does not match usr claim")
	}
}

func TestAuthenticator_allowsValidServiceTokenWithMatchingClientID(t *testing.T) {
	a := newAuth(t, &stubVerifier{claims: &auth.Claims{
		Kind: auth.TokenKindService, Subject: "svc-mqtt", ClientID: "svc-mqtt",
	}})
	ok, err := a.Authenticate(context.Background(), "svc-mqtt", "tok")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !ok {
		t.Errorf("expected allow")
	}
}

func TestAuthenticator_deniesServiceTokenWithWrongClientID(t *testing.T) {
	a := newAuth(t, &stubVerifier{claims: &auth.Claims{
		Kind: auth.TokenKindService, Subject: "svc-mqtt", ClientID: "svc-mqtt",
	}})
	ok, err := a.Authenticate(context.Background(), "other-client", "tok")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ok {
		t.Errorf("expected deny")
	}
}

func TestAuthenticator_propagatesExpiredAsDenyNotError(t *testing.T) {
	// Expired tokens are a clean denial (cgo layer returns MOSQ_ERR_AUTH).
	// They are NOT a plugin error — the broker shouldn't log expiry as a
	// fault.
	a := newAuth(t, &stubVerifier{err: auth.ErrTokenExpired})
	ok, err := a.Authenticate(context.Background(), "alice", "tok")
	if err != nil {
		t.Errorf("expired should not return an error: %v", err)
	}
	if ok {
		t.Errorf("expired should deny")
	}
}

func TestAuthenticator_propagatesInvalidAsDenyNotError(t *testing.T) {
	a := newAuth(t, &stubVerifier{err: auth.ErrTokenInvalid})
	ok, err := a.Authenticate(context.Background(), "alice", "tok")
	if err != nil {
		t.Errorf("invalid should not return an error: %v", err)
	}
	if ok {
		t.Errorf("invalid should deny")
	}
}

func TestAuthenticator_propagatesUnexpectedErrorToCaller(t *testing.T) {
	// Any non-sentinel error is a plumbing failure (e.g. JWKS unreachable
	// with cold cache). The cgo layer needs to know so it can log loudly.
	boom := errors.New("jwks unreachable")
	a := newAuth(t, &stubVerifier{err: boom})
	ok, err := a.Authenticate(context.Background(), "alice", "tok")
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want wraps %v", err, boom)
	}
	if ok {
		t.Errorf("plumbing failure must deny by default")
	}
}

func TestAuthenticator_deniesEmptyPassword(t *testing.T) {
	a := newAuth(t, &stubVerifier{claims: &auth.Claims{Kind: auth.TokenKindUser, Username: "alice"}})
	ok, err := a.Authenticate(context.Background(), "alice", "")
	if err != nil {
		t.Errorf("empty password should not error: %v", err)
	}
	if ok {
		t.Errorf("empty password must deny")
	}
}

func TestAuthenticator_deniesEmptyUsername(t *testing.T) {
	// Even if RequireUsernameMatch is on, an empty username is suspicious
	// enough that we deny without consulting the verifier. (An empty
	// username could match an empty Principal from a malformed token.)
	a := newAuth(t, &stubVerifier{claims: &auth.Claims{Kind: auth.TokenKindUser, Username: ""}})
	ok, err := a.Authenticate(context.Background(), "", "tok")
	if err != nil {
		t.Errorf("empty username should not error: %v", err)
	}
	if ok {
		t.Errorf("empty username must deny")
	}
}

func TestAuthenticator_requireUsernameMatchOff_acceptsAnyUsername(t *testing.T) {
	a := newAuth(t, &stubVerifier{claims: &auth.Claims{
		Kind: auth.TokenKindUser, Username: "alice",
	}}, func(c *auth.AuthenticatorConfig) {
		c.RequireUsernameMatch = false
	})
	ok, err := a.Authenticate(context.Background(), "any-name-goes", "tok")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !ok {
		t.Errorf("expected allow with username binding disabled")
	}
}

func TestAuthenticator_requireUsernameMatchOff_stillRejectsInvalidToken(t *testing.T) {
	// Off means we don't bind to a username — it does not mean we skip
	// JWT verification.
	a := newAuth(t, &stubVerifier{err: auth.ErrTokenInvalid}, func(c *auth.AuthenticatorConfig) {
		c.RequireUsernameMatch = false
	})
	ok, _ := a.Authenticate(context.Background(), "any", "tok")
	if ok {
		t.Errorf("invalid token must still be denied even with username binding off")
	}
}

func TestAuthenticator_integrationWithJWKSVerifier(t *testing.T) {
	// One end-to-end test wiring the real verifier through TestIdentity,
	// so we know the pieces fit together. The unit tests above prove the
	// decision logic in isolation.
	id := testutil.NewTestIdentity(t)
	v, err := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{
		Issuer: id.Issuer, JWKSURL: id.JWKSURL(),
	})
	if err != nil {
		t.Fatalf("NewJWKSVerifier: %v", err)
	}
	a := newAuth(t, v)

	tok := id.MintUserToken(t, testutil.UserClaims{
		Subject: "u-1", Username: "alice", Role: "user", Active: true,
	})
	if ok, err := a.Authenticate(context.Background(), "alice", tok); !ok || err != nil {
		t.Errorf("end-to-end allow: ok=%v err=%v", ok, err)
	}
	if ok, err := a.Authenticate(context.Background(), "mallory", tok); ok || err != nil {
		t.Errorf("end-to-end deny on mismatched username: ok=%v err=%v", ok, err)
	}
}
