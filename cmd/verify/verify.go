package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/sweeney/mqtt-auth/internal/auth"
)

// Exit codes are part of the CLI contract. Scripts that wrap mqtt-auth-verify
// in CI or in a broker health check rely on these specific values.
const (
	exitAccept     = 0 // token verifies (and username matches if checked)
	exitDeny       = 1 // clean denial — broker would refuse this CONNECT
	exitPlumbing   = 2 // JWKS unreachable, bad config, etc.
)

// flags collects every CLI option. Kept separate from run() so tests can
// build them by hand without going through flag.Parse.
type flags struct {
	issuer   string
	jwksURL  string
	username string
	file     string
	asJSON   bool
	token    string // positional, resolved after Parse
}

// run is the testable entrypoint. main calls it with os.Args[1:] and the real
// streams; tests call it with hand-built slices and *bytes.Buffer.
func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mqtt-auth-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, `mqtt-auth-verify: validate a JWT the way the mosquitto plugin would.

Usage:
  mqtt-auth-verify [flags] [token]
  echo "$TOKEN" | mqtt-auth-verify [flags]
  mqtt-auth-verify [flags] -file PATH

Flags:
`)
		fs.PrintDefaults()
		fmt.Fprintf(stderr, `
Exit codes:
  0  token verifies (and username matches if -username given)
  1  clean denial — broker would refuse this CONNECT
  2  plumbing failure — JWKS unreachable, bad config

`)
	}

	var f flags
	fs.StringVar(&f.issuer, "issuer", "https://id.swee.net", "expected `iss` claim")
	fs.StringVar(&f.jwksURL, "jwks", "", "JWKS URL (default: {issuer}/.well-known/jwks.json)")
	fs.StringVar(&f.username, "username", "", "MQTT username to check binding against (empty: skip binding)")
	fs.StringVar(&f.file, "file", "", "read token from PATH (use `-` for stdin)")
	fs.BoolVar(&f.asJSON, "json", false, "emit JSON instead of human-readable output")

	if err := fs.Parse(args); err != nil {
		// flag.ContinueOnError prints its own message + usage on error.
		// flag.ErrHelp is returned for -h/-help; treat that as success.
		if errors.Is(err, flag.ErrHelp) {
			return exitAccept
		}
		return exitPlumbing
	}

	if f.jwksURL == "" {
		f.jwksURL = strings.TrimRight(f.issuer, "/") + "/.well-known/jwks.json"
	}

	tok, err := readToken(fs.Args(), f.file, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitPlumbing
	}
	f.token = tok

	v, err := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{
		Issuer:     f.issuer,
		JWKSURL:    f.jwksURL,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	})
	if err != nil {
		fmt.Fprintf(stderr, "error: build verifier: %v\n", err)
		return exitPlumbing
	}

	claims, parseErr := v.Parse(ctx, f.token)
	result := verdict(claims, parseErr, f.username)

	if f.asJSON {
		_ = json.NewEncoder(stdout).Encode(result)
	} else {
		writeHuman(stdout, result)
	}

	switch {
	case result.WouldAuthenticate:
		return exitAccept
	case result.PlumbingError:
		return exitPlumbing
	default:
		return exitDeny
	}
}

// readToken figures out where the token came from. Precedence:
//
//  1. -file PATH (use "-" to mean stdin)
//  2. first positional arg
//  3. stdin
//
// Returns an error only if a chosen source can't be read. Trims trailing
// whitespace — copy-paste from a terminal often adds a newline.
func readToken(positional []string, file string, stdin io.Reader) (string, error) {
	switch {
	case file == "-":
		b, err := io.ReadAll(stdin)
		if err != nil {
			return "", fmt.Errorf("read stdin: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", file, err)
		}
		return strings.TrimSpace(string(b)), nil
	case len(positional) > 0:
		return strings.TrimSpace(positional[0]), nil
	default:
		b, err := io.ReadAll(stdin)
		if err != nil {
			return "", fmt.Errorf("read stdin: %w", err)
		}
		t := strings.TrimSpace(string(b))
		if t == "" {
			return "", errors.New("no token provided (pass as argv, via -file, or pipe via stdin)")
		}
		return t, nil
	}
}

// Result is the shape of the JSON output and the input to writeHuman.
type Result struct {
	Verdict           string   `json:"verdict"`              // "valid" | "expired" | "invalid" | "username_mismatch" | "plumbing_error"
	WouldAuthenticate bool     `json:"would_authenticate"`   // would the broker accept this CONNECT?
	Reason            string   `json:"reason,omitempty"`     // human-readable explanation
	PlumbingError     bool     `json:"plumbing_error"`       // true if -issuer/-jwks is wrong or unreachable
	Kind              string   `json:"kind,omitempty"`       // "user" | "service"
	Principal         string   `json:"principal,omitempty"`  // usr (or client_id) (or sub)
	Subject           string   `json:"sub,omitempty"`
	Issuer            string   `json:"iss,omitempty"`
	Audience          []string `json:"aud,omitempty"`
	Role              string   `json:"rol,omitempty"`
	Active            *bool    `json:"act,omitempty"`
	ClientID          string   `json:"client_id,omitempty"`
	Scope             string   `json:"scope,omitempty"`
	JTI               string   `json:"jti,omitempty"`
	IssuedAt          string   `json:"iat,omitempty"`
	ExpiresAt         string   `json:"exp,omitempty"`
	ExpiresIn         string   `json:"expires_in,omitempty"` // relative, e.g. "in 14m" or "1h ago"
}

// verdict turns Parse's outcome into the structured Result we emit.
// requireUsername is empty → skip username binding (just verify signature
// + claims). Non-empty → enforce the same binding the plugin does.
func verdict(claims *auth.Claims, parseErr error, requireUsername string) Result {
	if parseErr != nil {
		switch {
		case errors.Is(parseErr, auth.ErrTokenExpired):
			return Result{Verdict: "expired", Reason: "token is past its exp claim"}
		case errors.Is(parseErr, auth.ErrTokenInvalid):
			return Result{Verdict: "invalid", Reason: cleanErr(parseErr)}
		default:
			return Result{
				Verdict:       "plumbing_error",
				Reason:        cleanErr(parseErr),
				PlumbingError: true,
			}
		}
	}

	r := Result{
		Verdict:   "valid",
		Kind:      claims.Kind.String(),
		Subject:   claims.Subject,
		Issuer:    claims.Issuer,
		Audience:  claims.Audience,
		Role:      claims.Role,
		ClientID:  claims.ClientID,
		Scope:     claims.Scope,
		JTI:       claims.JTI,
	}
	if claims.Kind == auth.TokenKindUser {
		// Only expose `act` for user tokens — service tokens don't carry it.
		act := claims.Active
		r.Active = &act
	}
	if principal, ok := claims.Principal(); ok {
		r.Principal = principal
	}
	if claims.IssuedAt != 0 {
		r.IssuedAt = time.Unix(claims.IssuedAt, 0).UTC().Format(time.RFC3339)
	}
	if claims.ExpiresAt != 0 {
		exp := time.Unix(claims.ExpiresAt, 0).UTC()
		r.ExpiresAt = exp.Format(time.RFC3339)
		r.ExpiresIn = relTime(exp)
	}

	r.WouldAuthenticate = true
	if requireUsername != "" {
		principal, _ := claims.Principal()
		if principal != requireUsername {
			r.Verdict = "username_mismatch"
			r.WouldAuthenticate = false
			r.Reason = fmt.Sprintf("MQTT username %q does not match token principal %q",
				requireUsername, principal)
		}
	}
	return r
}

// cleanErr strips the redundant "token invalid: " prefix that the verifier
// adds when wrapping the underlying jwt library's error.
func cleanErr(err error) string {
	s := err.Error()
	for _, prefix := range []string{"token invalid: ", "verify: "} {
		s = strings.TrimPrefix(s, prefix)
	}
	return s
}

// relTime returns a short human-readable string for how far t is from now.
func relTime(t time.Time) string {
	d := time.Until(t)
	if d >= 0 {
		return "in " + truncDur(d).String()
	}
	return truncDur(-d).String() + " ago"
}

func truncDur(d time.Duration) time.Duration {
	switch {
	case d >= time.Hour:
		return d.Round(time.Minute)
	case d >= time.Minute:
		return d.Round(time.Second)
	default:
		return d.Round(100 * time.Millisecond)
	}
}

func writeHuman(w io.Writer, r Result) {
	if r.WouldAuthenticate {
		fmt.Fprintf(w, "✓ Token valid")
		if r.Reason != "" {
			fmt.Fprintf(w, " — %s", r.Reason)
		}
		fmt.Fprintln(w)
	} else {
		fmt.Fprintf(w, "✗ Token would not authenticate (%s)\n", r.Verdict)
		if r.Reason != "" {
			fmt.Fprintf(w, "  Reason:    %s\n", r.Reason)
		}
	}
	if r.Kind != "" {
		fmt.Fprintf(w, "  Kind:      %s\n", r.Kind)
	}
	if r.Principal != "" {
		fmt.Fprintf(w, "  Principal: %s\n", r.Principal)
	}
	if r.Subject != "" {
		fmt.Fprintf(w, "  Subject:   %s\n", r.Subject)
	}
	if r.Issuer != "" {
		fmt.Fprintf(w, "  Issuer:    %s\n", r.Issuer)
	}
	if len(r.Audience) > 0 {
		fmt.Fprintf(w, "  Audience:  %s\n", strings.Join(r.Audience, ", "))
	}
	if r.Role != "" {
		fmt.Fprintf(w, "  Role:      %s\n", r.Role)
	}
	if r.Active != nil {
		fmt.Fprintf(w, "  Active:    %v\n", *r.Active)
	}
	if r.ClientID != "" {
		fmt.Fprintf(w, "  ClientID:  %s\n", r.ClientID)
	}
	if r.Scope != "" {
		fmt.Fprintf(w, "  Scope:     %s\n", r.Scope)
	}
	if r.IssuedAt != "" {
		fmt.Fprintf(w, "  IssuedAt:  %s\n", r.IssuedAt)
	}
	if r.ExpiresAt != "" {
		fmt.Fprintf(w, "  ExpiresAt: %s (%s)\n", r.ExpiresAt, r.ExpiresIn)
	}
	if r.JTI != "" {
		fmt.Fprintf(w, "  JTI:       %s\n", r.JTI)
	}
}
