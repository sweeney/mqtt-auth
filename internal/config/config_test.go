package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/sweeney/mqtt-auth/internal/config"
)

func TestParse_minimumValidConfig(t *testing.T) {
	c, err := config.Parse(map[string]string{
		"jwt_issuer": "https://id.swee.net",
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.JWTIssuer != "https://id.swee.net" {
		t.Errorf("JWTIssuer = %q", c.JWTIssuer)
	}
	// JWKS URL defaults to issuer + /.well-known/jwks.json.
	if want := "https://id.swee.net/.well-known/jwks.json"; c.JWKSURL != want {
		t.Errorf("JWKSURL = %q, want %q", c.JWKSURL, want)
	}
	// Defaults.
	if c.JWKSCacheTTL != 5*time.Minute {
		t.Errorf("JWKSCacheTTL = %v, want 5m", c.JWKSCacheTTL)
	}
	if c.JWKSRefetchMin != 10*time.Second {
		t.Errorf("JWKSRefetchMin = %v, want 10s", c.JWKSRefetchMin)
	}
	if c.HTTPTimeout != 10*time.Second {
		t.Errorf("HTTPTimeout = %v, want 10s", c.HTTPTimeout)
	}
	if !c.RequireUsernameMatch {
		t.Errorf("RequireUsernameMatch should default to true")
	}
}

func TestParse_explicitJWKSURLOverridesDefault(t *testing.T) {
	c, err := config.Parse(map[string]string{
		"jwt_issuer":   "https://id.swee.net",
		"jwt_jwks_url": "https://keys.example.com/jwks",
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.JWKSURL != "https://keys.example.com/jwks" {
		t.Errorf("JWKSURL = %q", c.JWKSURL)
	}
}

func TestParse_durationsAndBoolsParseFromStrings(t *testing.T) {
	c, err := config.Parse(map[string]string{
		"jwt_issuer":              "https://id.swee.net",
		"jwt_jwks_cache_ttl":      "30s",
		"jwt_jwks_refetch_min":    "2s",
		"jwt_http_timeout":        "1s",
		"require_username_match":  "false",
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.JWKSCacheTTL != 30*time.Second {
		t.Errorf("JWKSCacheTTL = %v", c.JWKSCacheTTL)
	}
	if c.JWKSRefetchMin != 2*time.Second {
		t.Errorf("JWKSRefetchMin = %v", c.JWKSRefetchMin)
	}
	if c.HTTPTimeout != time.Second {
		t.Errorf("HTTPTimeout = %v", c.HTTPTimeout)
	}
	if c.RequireUsernameMatch {
		t.Errorf("RequireUsernameMatch should be false")
	}
}

func TestParse_requiresIssuer(t *testing.T) {
	_, err := config.Parse(map[string]string{})
	if err == nil {
		t.Fatal("expected error when jwt_issuer is missing")
	}
	if !strings.Contains(err.Error(), "jwt_issuer") {
		t.Errorf("err message should mention jwt_issuer, got: %v", err)
	}
}

func TestParse_rejectsInvalidDuration(t *testing.T) {
	_, err := config.Parse(map[string]string{
		"jwt_issuer":         "https://id.swee.net",
		"jwt_jwks_cache_ttl": "nonsense",
	})
	if err == nil {
		t.Error("expected error on bad duration")
	}
}

func TestParse_rejectsNegativeDuration(t *testing.T) {
	_, err := config.Parse(map[string]string{
		"jwt_issuer":         "https://id.swee.net",
		"jwt_jwks_cache_ttl": "-5m",
	})
	if err == nil {
		t.Error("expected error on negative duration")
	}
}

func TestParse_rejectsInvalidBool(t *testing.T) {
	_, err := config.Parse(map[string]string{
		"jwt_issuer":             "https://id.swee.net",
		"require_username_match": "perhaps",
	})
	if err == nil {
		t.Error("expected error on bad bool")
	}
}

func TestParse_rejectsUnknownOption(t *testing.T) {
	// Strict parsing: a typo like jwt_issuser shouldn't silently fall back
	// to defaults.
	_, err := config.Parse(map[string]string{
		"jwt_issuer":  "https://id.swee.net",
		"jwt_issuser": "https://typo.example.com",
	})
	if err == nil {
		t.Error("expected error on unknown option")
	}
}

func TestParse_acceptsBoolVariants(t *testing.T) {
	for _, v := range []string{"true", "TRUE", "1", "yes", "on"} {
		c, err := config.Parse(map[string]string{
			"jwt_issuer":             "https://id.swee.net",
			"require_username_match": v,
		})
		if err != nil {
			t.Errorf("%q: %v", v, err)
			continue
		}
		if !c.RequireUsernameMatch {
			t.Errorf("%q should parse as true", v)
		}
	}
	for _, v := range []string{"false", "FALSE", "0", "no", "off"} {
		c, err := config.Parse(map[string]string{
			"jwt_issuer":             "https://id.swee.net",
			"require_username_match": v,
		})
		if err != nil {
			t.Errorf("%q: %v", v, err)
			continue
		}
		if c.RequireUsernameMatch {
			t.Errorf("%q should parse as false", v)
		}
	}
}
