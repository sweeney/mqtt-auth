package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/sync/singleflight"
)

// Sentinel errors that callers may distinguish. All other failures collapse
// into ErrTokenInvalid — the broker only needs to know yes/no, and revealing
// finer-grained reasons over the MQTT wire helps attackers more than users.
var (
	// ErrTokenInvalid covers signature mismatch, wrong issuer, unknown
	// signing key, malformed JWT, missing required headers, and anything
	// else that isn't expiry.
	ErrTokenInvalid = errors.New("token invalid")
	// ErrTokenExpired is returned when the exp claim is in the past.
	// Surfaced separately because some callers may want to log it
	// differently (it's the normal end-of-life path).
	ErrTokenExpired = errors.New("token expired")
)

// Verifier validates a JWT and returns its parsed claims.
type Verifier interface {
	Parse(ctx context.Context, tokenStr string) (*Claims, error)
}

// JWKSVerifierConfig configures a JWKSVerifier.
type JWKSVerifierConfig struct {
	// Issuer is the expected `iss` claim. Required.
	Issuer string
	// JWKSURL is the fully-qualified URL of the JWK Set document.
	// Required.
	JWKSURL string
	// HTTPClient is used for JWKS fetches. Defaults to a client with a
	// 10s timeout.
	HTTPClient *http.Client
	// CacheTTL is how long fetched keys are considered fresh before the
	// next Parse call triggers a refetch. Defaults to 5 minutes.
	CacheTTL time.Duration
	// RefetchMinInterval throttles refetches triggered by a kid miss, so
	// a flood of bad tokens cannot stampede the JWKS endpoint. Defaults
	// to 10 seconds.
	RefetchMinInterval time.Duration
}

// JWKSVerifier validates ES256 JWTs against a JWKS endpoint. Keys are cached
// in memory; the cache refreshes on time-based invalidation and on `kid`
// miss. Concurrent refetches are deduplicated via singleflight, and if a
// refetch fails while a stale-but-known key is still cached, the stale key
// is used rather than failing all auth.
type JWKSVerifier struct {
	issuer     string
	jwksURL    string
	httpClient *http.Client
	cacheTTL   time.Duration
	refetchMin time.Duration

	sf singleflight.Group

	mu         sync.RWMutex
	keys       map[string]*ecdsa.PublicKey
	fetchedAt  time.Time
	lastMissAt time.Time
}

// Defaults.
const (
	defaultCacheTTL    = 5 * time.Minute
	defaultRefetchMin  = 10 * time.Second
	defaultHTTPTimeout = 10 * time.Second
)

// NewJWKSVerifier constructs a verifier. No network I/O occurs here — the
// JWKS is fetched lazily on the first Parse call.
func NewJWKSVerifier(cfg JWKSVerifierConfig) (*JWKSVerifier, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("issuer is required")
	}
	if cfg.JWKSURL == "" {
		return nil, errors.New("jwks url is required")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultHTTPTimeout}
	}
	ttl := cfg.CacheTTL
	if ttl == 0 {
		ttl = defaultCacheTTL
	}
	refetch := cfg.RefetchMinInterval
	if refetch == 0 {
		refetch = defaultRefetchMin
	}
	return &JWKSVerifier{
		issuer:     cfg.Issuer,
		jwksURL:    cfg.JWKSURL,
		httpClient: client,
		cacheTTL:   ttl,
		refetchMin: refetch,
		keys:       map[string]*ecdsa.PublicKey{},
	}, nil
}

// Parse verifies tokenStr and returns its claims. Returns ErrTokenExpired
// when the token has expired and ErrTokenInvalid for any other failure. The
// ctx bounds JWKS refetches.
func (v *JWKSVerifier) Parse(ctx context.Context, tokenStr string) (*Claims, error) {
	if tokenStr == "" {
		return nil, ErrTokenInvalid
	}

	mc := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(
		tokenStr,
		mc,
		v.keyFunc(ctx),
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithIssuer(v.issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}
	if !tok.Valid {
		return nil, ErrTokenInvalid
	}

	kind := classifyKind(tok.Header)
	c, err := buildClaims(mc, kind)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}
	return c, nil
}

// keyFunc returns the jwt.Keyfunc that resolves the verifying key for a
// parse. Captures ctx so the closure can bound any JWKS refetch.
func (v *JWKSVerifier) keyFunc(ctx context.Context) jwt.Keyfunc {
	return func(t *jwt.Token) (any, error) {
		// Defence-in-depth: WithValidMethods already restricts to ES256,
		// but assert the method type too in case the library is ever
		// reconfigured.
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid in token header")
		}
		return v.keyForKid(ctx, kid)
	}
}

// keyForKid returns the public key for a given kid, refetching JWKS if the
// kid is unknown or the cache has gone stale. Refetch failures are tolerated
// when a usable key is still in cache.
func (v *JWKSVerifier) keyForKid(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	v.mu.RLock()
	key, have := v.keys[kid]
	stale := time.Since(v.fetchedAt) > v.cacheTTL
	throttled := !have && !v.fetchedAt.IsZero() && time.Since(v.lastMissAt) < v.refetchMin
	v.mu.RUnlock()

	if have && !stale {
		return key, nil
	}
	if !have && throttled {
		return nil, fmt.Errorf("unknown kid %q (refetch throttled)", kid)
	}

	// Deduplicate concurrent refetches: N concurrent cold misses produce
	// one outbound request. Key is constant — JWKS is a single resource.
	_, err, _ := v.sf.Do("jwks", func() (any, error) {
		v.mu.RLock()
		_, reHave := v.keys[kid]
		reStale := time.Since(v.fetchedAt) > v.cacheTTL
		v.mu.RUnlock()
		if reHave && !reStale {
			return nil, nil
		}
		return nil, v.refetch(ctx)
	})

	v.mu.RLock()
	key, have = v.keys[kid]
	v.mu.RUnlock()

	if err != nil {
		// Refetch failed but we still have a cached key for this kid:
		// prefer serving the stale key over failing all auth on a
		// transient JWKS blip.
		if have {
			log.Printf("mqtt-auth: jwks refetch failed, serving cached key for kid %q: %v", kid, err)
			return key, nil
		}
		v.mu.Lock()
		v.lastMissAt = time.Now()
		v.mu.Unlock()
		return nil, err
	}

	if !have {
		v.mu.Lock()
		v.lastMissAt = time.Now()
		v.mu.Unlock()
		return nil, fmt.Errorf("unknown kid %q after refetch", kid)
	}
	return key, nil
}

// refetch fetches JWKS and atomically replaces the in-memory cache on
// success. HTTP I/O happens without v.mu held; only the final swap takes
// the write lock.
func (v *JWKSVerifier) refetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("build jwks request: %w", err)
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks status %d", resp.StatusCode)
	}

	var set jwkSet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return fmt.Errorf("decode jwks: %w", err)
	}

	keys := make(map[string]*ecdsa.PublicKey, len(set.Keys))
	for _, j := range set.Keys {
		if j.Kty != "EC" || j.Crv != "P-256" || j.Kid == "" {
			continue
		}
		pub, err := jwkToECDSAPublic(j)
		if err != nil {
			continue
		}
		keys[j.Kid] = pub
	}
	if len(keys) == 0 {
		return errors.New("jwks contained no usable keys")
	}

	v.mu.Lock()
	v.keys = keys
	v.fetchedAt = time.Now()
	v.mu.Unlock()
	return nil
}

// classifyKind inspects the JOSE header to decide whether a token is a user
// or service token. RFC 9068 service tokens carry typ=at+jwt.
func classifyKind(header map[string]any) TokenKind {
	if typ, _ := header["typ"].(string); typ == "at+jwt" {
		return TokenKindService
	}
	return TokenKindUser
}

// buildClaims projects the verified MapClaims into our typed Claims struct.
func buildClaims(mc jwt.MapClaims, kind TokenKind) (*Claims, error) {
	c := &Claims{Kind: kind}
	if iss, ok := mc["iss"].(string); ok {
		c.Issuer = iss
	}
	if sub, ok := mc["sub"].(string); ok {
		c.Subject = sub
	}
	if jti, ok := mc["jti"].(string); ok {
		c.JTI = jti
	}
	c.Audience = audSlice(mc["aud"])
	c.ExpiresAt = numericClaim(mc["exp"])
	c.IssuedAt = numericClaim(mc["iat"])

	switch kind {
	case TokenKindUser:
		if u, ok := mc["usr"].(string); ok {
			c.Username = u
		}
		if r, ok := mc["rol"].(string); ok {
			c.Role = r
		}
		if a, ok := mc["act"].(bool); ok {
			c.Active = a
		}
	case TokenKindService:
		if cid, ok := mc["client_id"].(string); ok {
			c.ClientID = cid
		}
		if s, ok := mc["scope"].(string); ok {
			c.Scope = s
		}
	}
	return c, nil
}

func audSlice(v any) []string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func numericClaim(v any) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case int64:
		return t
	case int:
		return int64(t)
	case json.Number:
		n, _ := t.Int64()
		return n
	default:
		return 0
	}
}

// jwk / jwkSet are the on-wire JWKS shapes. Kept private so tests don't
// couple to them — testutil has its own JWK type for the server side.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

func jwkToECDSAPublic(j jwk) (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("decode jwk.x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(j.Y)
	if err != nil {
		return nil, fmt.Errorf("decode jwk.y: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

