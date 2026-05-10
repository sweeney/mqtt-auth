// Package config parses mosquitto auth_opt_* options into a typed Config.
//
// Mosquitto hands the plugin a map of string→string options. Parse validates
// that map, fills in defaults, and rejects unknown keys so typos don't
// silently degrade to defaults.
package config

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Config is the fully resolved plugin configuration.
type Config struct {
	// JWTIssuer is the expected "iss" claim. Required.
	JWTIssuer string
	// JWKSURL is the fully-qualified JWKS endpoint. Defaults to
	// JWTIssuer + "/.well-known/jwks.json".
	JWKSURL string
	// JWKSCacheTTL is how long fetched keys are considered fresh.
	JWKSCacheTTL time.Duration
	// JWKSRefetchMin throttles refetches triggered by a kid miss.
	JWKSRefetchMin time.Duration
	// HTTPTimeout bounds each JWKS HTTP request.
	HTTPTimeout time.Duration
	// RequireUsernameMatch enforces MQTT username == token principal.
	// Defaults to true.
	RequireUsernameMatch bool
}

// Defaults applied when the corresponding option is unset.
const (
	defaultCacheTTL    = 5 * time.Minute
	defaultRefetchMin  = 10 * time.Second
	defaultHTTPTimeout = 10 * time.Second
)

// Known option keys. Listed here so Parse can reject typos.
var knownOptions = map[string]struct{}{
	"jwt_issuer":             {},
	"jwt_jwks_url":           {},
	"jwt_jwks_cache_ttl":     {},
	"jwt_jwks_refetch_min":   {},
	"jwt_http_timeout":       {},
	"require_username_match": {},
}

// Parse turns the mosquitto auth_opt_* map into a Config. Returns an error
// listing all problems found (missing required, bad values, unknown keys).
func Parse(opts map[string]string) (*Config, error) {
	c := &Config{
		JWKSCacheTTL:         defaultCacheTTL,
		JWKSRefetchMin:       defaultRefetchMin,
		HTTPTimeout:          defaultHTTPTimeout,
		RequireUsernameMatch: true,
	}

	var errs []string

	for k := range opts {
		if _, ok := knownOptions[k]; !ok {
			errs = append(errs, fmt.Sprintf("unknown option %q", k))
		}
	}

	c.JWTIssuer = strings.TrimSpace(opts["jwt_issuer"])
	if c.JWTIssuer == "" {
		errs = append(errs, "jwt_issuer is required")
	}

	if v := strings.TrimSpace(opts["jwt_jwks_url"]); v != "" {
		c.JWKSURL = v
	} else if c.JWTIssuer != "" {
		c.JWKSURL = strings.TrimRight(c.JWTIssuer, "/") + "/.well-known/jwks.json"
	}

	if v, ok := opts["jwt_jwks_cache_ttl"]; ok {
		d, err := parsePositiveDuration("jwt_jwks_cache_ttl", v)
		if err != nil {
			errs = append(errs, err.Error())
		} else {
			c.JWKSCacheTTL = d
		}
	}
	if v, ok := opts["jwt_jwks_refetch_min"]; ok {
		d, err := parsePositiveDuration("jwt_jwks_refetch_min", v)
		if err != nil {
			errs = append(errs, err.Error())
		} else {
			c.JWKSRefetchMin = d
		}
	}
	if v, ok := opts["jwt_http_timeout"]; ok {
		d, err := parsePositiveDuration("jwt_http_timeout", v)
		if err != nil {
			errs = append(errs, err.Error())
		} else {
			c.HTTPTimeout = d
		}
	}
	if v, ok := opts["require_username_match"]; ok {
		b, err := parseBool("require_username_match", v)
		if err != nil {
			errs = append(errs, err.Error())
		} else {
			c.RequireUsernameMatch = b
		}
	}

	if len(errs) > 0 {
		return nil, errors.New("config: " + strings.Join(errs, "; "))
	}
	return c, nil
}

func parsePositiveDuration(key, value string) (time.Duration, error) {
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a valid duration (e.g. \"5m\", \"30s\")", key, value)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s: must be positive, got %v", key, d)
	}
	return d, nil
}

func parseBool(key, value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes", "on":
		return true, nil
	case "false", "0", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("%s: %q is not a valid boolean (true/false/1/0/yes/no/on/off)", key, value)
	}
}
