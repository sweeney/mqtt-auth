// Package testutil provides a fake identity service for tests.
//
// A TestIdentity mints JWTs signed by an in-memory ECDSA P-256 key and serves
// the matching JWK Set over a httptest.Server. Tests can mint valid tokens,
// expired tokens, tokens signed by a wrong key, etc., and point the code under
// test at the TestIdentity's URL.
package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWK is one entry in a JWK Set, matching the shape identity itself serves.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// JWKSet is the document served at /.well-known/jwks.json.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// TestIdentity is an in-test stand-in for id.swee.net. It owns a signing key,
// exposes a JWKS endpoint, and can mint user and service tokens.
type TestIdentity struct {
	Issuer string

	mu        sync.RWMutex
	keys      []*signingKey
	server    *httptest.Server
	jwksHits  int
	jwksDelay time.Duration
	jwksFail  bool
}

type signingKey struct {
	priv *ecdsa.PrivateKey
	kid  string
}

// NewTestIdentity starts a httptest.Server serving JWKS at /.well-known/jwks.json
// and returns the identity. The caller must Close it when done. The Issuer
// field is initialised to the server's URL so it matches the iss claim of
// minted tokens by default.
func NewTestIdentity(t *testing.T) *TestIdentity {
	t.Helper()
	id := &TestIdentity{}
	id.addKey(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", id.serveJWKS)
	id.server = httptest.NewServer(mux)
	id.Issuer = id.server.URL
	t.Cleanup(id.Close)
	return id
}

// Close shuts down the httptest server.
func (id *TestIdentity) Close() {
	if id.server != nil {
		id.server.Close()
		id.server = nil
	}
}

// URL is the base URL of the identity's HTTP server.
func (id *TestIdentity) URL() string { return id.server.URL }

// JWKSURL is the full URL of the JWKS endpoint.
func (id *TestIdentity) JWKSURL() string { return id.server.URL + "/.well-known/jwks.json" }

// JWKSHits returns the number of successful GETs to the JWKS endpoint.
// Useful for asserting that the cache is being honoured.
func (id *TestIdentity) JWKSHits() int {
	id.mu.RLock()
	defer id.mu.RUnlock()
	return id.jwksHits
}

// SetJWKSFail toggles whether the JWKS endpoint returns 500.
func (id *TestIdentity) SetJWKSFail(fail bool) {
	id.mu.Lock()
	id.jwksFail = fail
	id.mu.Unlock()
}

// SetJWKSDelay introduces an artificial delay on JWKS responses. Useful for
// exercising singleflight dedup and context cancellation.
func (id *TestIdentity) SetJWKSDelay(d time.Duration) {
	id.mu.Lock()
	id.jwksDelay = d
	id.mu.Unlock()
}

// RotateKey adds a fresh signing key and makes it the current (first) key.
// The previous key remains in the JWKS until DropOldestKey is called, so
// outstanding tokens still verify across a rotation.
func (id *TestIdentity) RotateKey(t *testing.T) {
	t.Helper()
	id.addKey(t)
	// addKey prepends, so the new key is at index 0. Nothing else needed.
}

// DropOldestKey removes the trailing key from the set. Use after RotateKey to
// simulate the previous key being retired.
func (id *TestIdentity) DropOldestKey() {
	id.mu.Lock()
	defer id.mu.Unlock()
	if len(id.keys) > 1 {
		id.keys = id.keys[:len(id.keys)-1]
	}
}

// CurrentKID returns the kid of the current signing key.
func (id *TestIdentity) CurrentKID() string {
	id.mu.RLock()
	defer id.mu.RUnlock()
	return id.keys[0].kid
}

// UserClaims is the minimal claim set for a user access token.
type UserClaims struct {
	Subject  string        // sub: user id
	Username string        // usr
	Role     string        // rol
	Active   bool          // act
	Audience string        // aud, optional
	TTL      time.Duration // defaults to 15m if zero
}

// ServiceClaims is the minimal claim set for an RFC 9068 service token.
type ServiceClaims struct {
	ClientID string        // sub + client_id
	Audience string        // aud (required for service tokens)
	Scope    string        // scope
	TTL      time.Duration // defaults to 1h if zero
}

// MintUserToken signs a user access token with the current key.
func (id *TestIdentity) MintUserToken(t *testing.T, c UserClaims) string {
	t.Helper()
	ttl := c.TTL
	if ttl == 0 {
		ttl = 15 * time.Minute
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": id.Issuer,
		"sub": c.Subject,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(ttl).Unix(),
		"jti": randomID(),
		"usr": c.Username,
		"rol": c.Role,
		"act": c.Active,
	}
	if c.Audience != "" {
		claims["aud"] = c.Audience
	}
	return id.signWithCurrent(t, claims, nil)
}

// MintServiceToken signs an RFC 9068 service token with the current key.
func (id *TestIdentity) MintServiceToken(t *testing.T, c ServiceClaims) string {
	t.Helper()
	ttl := c.TTL
	if ttl == 0 {
		ttl = time.Hour
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":       id.Issuer,
		"sub":       c.ClientID,
		"iat":       now.Unix(),
		"nbf":       now.Unix(),
		"exp":       now.Add(ttl).Unix(),
		"jti":       randomID(),
		"client_id": c.ClientID,
		"aud":       c.Audience,
	}
	if c.Scope != "" {
		claims["scope"] = c.Scope
	}
	hdr := map[string]any{"typ": "at+jwt"}
	return id.signWithCurrent(t, claims, hdr)
}

// MintCustom signs an arbitrary claim/header set, for negative tests that
// need to fiddle with iss, exp, kid, etc.
func (id *TestIdentity) MintCustom(t *testing.T, claims jwt.MapClaims, header map[string]any) string {
	t.Helper()
	return id.signWithCurrent(t, claims, header)
}

// MintWithKey signs claims with a caller-provided key and kid. The kid will
// NOT exist in the JWKS unless the caller adds it via InjectKey. Used to test
// signature rejection by an unknown signer.
func (id *TestIdentity) MintWithKey(t *testing.T, priv *ecdsa.PrivateKey, kid string, claims jwt.MapClaims, header map[string]any) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = kid
	for k, v := range header {
		tok.Header[k] = v
	}
	s, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign with foreign key: %v", err)
	}
	return s
}

// GenerateForeignKey returns a fresh ECDSA P-256 key not registered with this
// identity. Tests use this to mint tokens with valid-looking but untrusted
// signatures.
func GenerateForeignKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate foreign key: %v", err)
	}
	return k
}

func (id *TestIdentity) signWithCurrent(t *testing.T, claims jwt.MapClaims, header map[string]any) string {
	t.Helper()
	id.mu.RLock()
	cur := id.keys[0]
	id.mu.RUnlock()

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = cur.kid
	for k, v := range header {
		tok.Header[k] = v
	}
	s, err := tok.SignedString(cur.priv)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return s
}

func (id *TestIdentity) addKey(t *testing.T) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	k := &signingKey{priv: priv, kid: kidFor(&priv.PublicKey)}
	id.mu.Lock()
	id.keys = append([]*signingKey{k}, id.keys...)
	id.mu.Unlock()
}

func (id *TestIdentity) serveJWKS(w http.ResponseWriter, r *http.Request) {
	id.mu.Lock()
	hits := id.jwksHits + 1
	id.jwksHits = hits
	delay := id.jwksDelay
	fail := id.jwksFail
	keysCopy := append([]*signingKey(nil), id.keys...)
	id.mu.Unlock()

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
	}
	if fail {
		http.Error(w, "boom", http.StatusInternalServerError)
		return
	}

	set := JWKSet{Keys: make([]JWK, 0, len(keysCopy))}
	for _, k := range keysCopy {
		set.Keys = append(set.Keys, publicKeyToJWK(k.kid, &k.priv.PublicKey))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(set)
}

func kidFor(pub *ecdsa.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

func publicKeyToJWK(kid string, pub *ecdsa.PublicKey) JWK {
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	x := padLeft(pub.X.Bytes(), byteLen)
	y := padLeft(pub.Y.Bytes(), byteLen)
	return JWK{
		Kty: "EC",
		Use: "sig",
		Alg: "ES256",
		Kid: kid,
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(x),
		Y:   base64.RawURLEncoding.EncodeToString(y),
	}
}

func padLeft(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

func randomID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
