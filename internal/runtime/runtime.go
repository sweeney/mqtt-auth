// Package runtime is the pure-Go side of the mosquitto auth plugin.
//
// It has no cgo so it can be unit-tested in isolation. The cgo //export
// functions in package plugin call into here.
package runtime

import (
	"context"
	"errors"
	"log"
	"net/http"
	"sync/atomic"

	"github.com/sweeney/mqtt-auth/internal/auth"
	"github.com/sweeney/mqtt-auth/internal/config"
)

// Mosquitto return codes mirrored here so the runtime can produce them
// without importing cgo. Values must match mosquitto.h.
const (
	MosqErrSuccess     = 0
	MosqErrInval       = 3
	MosqErrAuth        = 11
	MosqErrACLDenied   = 12
	MosqErrUnknown     = 13
	MosqErrPluginDefer = 17
)

// state is the singleton state for the loaded plugin. There is exactly one
// per loaded .so. It is set by Init on plugin init and consulted by
// Authenticate on every CONNECT.
//
// Stored via atomic.Pointer so the unpwd hot path is lock-free: reads are
// just a pointer load, and the only writer is Init, which runs once during
// plugin load (and again on reload, never concurrently with reads).
var state atomic.Pointer[pluginState]

type pluginState struct {
	authenticator *auth.Authenticator
	cfg           *config.Config
}

// Init builds the runtime from raw auth_opt_* options. Returns a MOSQ_ERR
// code suitable for returning from mosquitto_auth_plugin_init.
//
// On failure it logs the cause and returns MOSQ_ERR_INVAL so mosquitto
// refuses to start with a misconfigured plugin (preferable to silently
// failing open).
func Init(opts map[string]string) int {
	cfg, err := config.Parse(opts)
	if err != nil {
		log.Printf("mqtt-auth: %v", err)
		return MosqErrInval
	}

	verifier, err := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{
		Issuer:             cfg.JWTIssuer,
		JWKSURL:            cfg.JWKSURL,
		CacheTTL:           cfg.JWKSCacheTTL,
		RefetchMinInterval: cfg.JWKSRefetchMin,
		HTTPClient:         &http.Client{Timeout: cfg.HTTPTimeout},
	})
	if err != nil {
		log.Printf("mqtt-auth: build verifier: %v", err)
		return MosqErrInval
	}

	authenticator, err := auth.NewAuthenticator(auth.AuthenticatorConfig{
		Verifier:             verifier,
		RequireUsernameMatch: cfg.RequireUsernameMatch,
	})
	if err != nil {
		log.Printf("mqtt-auth: build authenticator: %v", err)
		return MosqErrInval
	}

	state.Store(&pluginState{authenticator: authenticator, cfg: cfg})
	log.Printf("mqtt-auth: initialised (iss=%s jwks=%s require_username_match=%v)",
		cfg.JWTIssuer, cfg.JWKSURL, cfg.RequireUsernameMatch)
	return MosqErrSuccess
}

// Cleanup drops the global. mosquitto calls this on shutdown.
func Cleanup() {
	state.Store(nil)
}

// Authenticate is the runtime side of mosquitto_auth_unpwd_check. Returns
// a MOSQ_ERR code:
//   - SUCCESS: token verified and (if enforced) username matches.
//   - AUTH: clean rejection.
//   - UNKNOWN: plumbing failure (JWKS unreachable). Mosquitto treats this
//     as authentication failure but logs it as a server error.
func Authenticate(ctx context.Context, username, password string) int {
	r := state.Load()
	if r == nil {
		// Plugin was loaded but Init was never called or has been cleaned
		// up. Refuse to authenticate — fail closed.
		log.Printf("mqtt-auth: Authenticate called with nil state")
		return MosqErrUnknown
	}
	ok, err := r.authenticator.Authenticate(ctx, username, password)
	if err != nil {
		log.Printf("mqtt-auth: verify error for user %q: %v", username, err)
		return MosqErrUnknown
	}
	if !ok {
		return MosqErrAuth
	}
	return MosqErrSuccess
}

// CheckACL is the runtime side of mosquitto_auth_acl_check. v1: allow.
//
// Returns MOSQ_ERR_SUCCESS unconditionally. Topic-level authorisation will
// be added in a follow-up; until then a successful CONNECT implies full
// publish/subscribe rights, just like the broker's default behaviour
// without a plugin.
func CheckACL(username, topic string, access int) int {
	_ = username
	_ = topic
	_ = access
	return MosqErrSuccess
}

// OptsToMap copies a parallel keys/values slice (the shape cgo hands us)
// into a map suitable for the config parser. Lifted out so it can be unit
// tested without cgo. Returns an error on length mismatch.
func OptsToMap(keys, values []string) (map[string]string, error) {
	if len(keys) != len(values) {
		return nil, errors.New("OptsToMap: keys/values length mismatch")
	}
	m := make(map[string]string, len(keys))
	for i, k := range keys {
		m[k] = values[i]
	}
	return m, nil
}
