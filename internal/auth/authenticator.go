package auth

import (
	"context"
	"errors"
	"fmt"
)

// AuthenticatorConfig configures an Authenticator.
type AuthenticatorConfig struct {
	// Verifier validates the password field as a JWT. Required.
	Verifier Verifier

	// RequireUsernameMatch, when true (the default in production), requires
	// the MQTT username field to equal the token's Principal — that is,
	// the `usr` claim for user tokens or `client_id` for service tokens
	// (falling back to `sub` for either if those are absent).
	//
	// Disable only if you have a deliberate reason: it prevents a leaked
	// token from being used to authenticate as a different MQTT identity
	// than the one it was issued for.
	RequireUsernameMatch bool
}

// Authenticator decides whether a CONNECT should be accepted.
//
// The decision split:
//   - (true, nil): accept. Token verified and (if enabled) username matches
//     the token's principal.
//   - (false, nil): clean rejection. Token was invalid, expired, or did not
//     match the username. The cgo layer should return MOSQ_ERR_AUTH.
//   - (false, non-nil err): plumbing failure (e.g. JWKS unreachable with
//     a cold cache). The cgo layer should log loudly; default behaviour is
//     still to reject the connection so that an outage of the identity
//     service doesn't fail-open.
type Authenticator struct {
	verifier             Verifier
	requireUsernameMatch bool
}

// NewAuthenticator constructs an Authenticator.
func NewAuthenticator(cfg AuthenticatorConfig) (*Authenticator, error) {
	if cfg.Verifier == nil {
		return nil, errors.New("verifier is required")
	}
	return &Authenticator{
		verifier:             cfg.Verifier,
		requireUsernameMatch: cfg.RequireUsernameMatch,
	}, nil
}

// Authenticate validates a CONNECT's username/password pair, where password
// is expected to be a JWT issued by the configured identity service.
//
// See Authenticator's doc for the (bool, error) tri-state semantics.
func (a *Authenticator) Authenticate(ctx context.Context, username, password string) (bool, error) {
	if password == "" {
		return false, nil
	}
	if a.requireUsernameMatch && username == "" {
		// An empty MQTT username could spuriously match a token with no
		// principal claim. Refuse defensively.
		return false, nil
	}

	claims, err := a.verifier.Parse(ctx, password)
	if err != nil {
		if errors.Is(err, ErrTokenExpired) || errors.Is(err, ErrTokenInvalid) {
			return false, nil
		}
		// Unexpected: surface so the cgo layer can log it. We still deny.
		return false, fmt.Errorf("verify: %w", err)
	}

	if !a.requireUsernameMatch {
		return true, nil
	}

	principal, ok := claims.Principal()
	if !ok {
		return false, nil
	}
	if principal != username {
		return false, nil
	}
	return true, nil
}
