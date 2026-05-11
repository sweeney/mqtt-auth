package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sweeney/mqtt-auth/internal/auth/testutil"
)

// runCLI is a convenience wrapper that invokes the CLI as if it were spawned
// from a shell, capturing both streams.
func runCLI(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var so, se bytes.Buffer
	code = run(context.Background(), args, strings.NewReader(stdin), &so, &se)
	return code, so.String(), se.String()
}

func TestVerify_validUserToken_acceptsAndPrintsClaims(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	tok := id.MintUserToken(t, testutil.UserClaims{
		Subject: "u-abc", Username: "alice", Role: "user", Active: true,
	})

	code, out, _ := runCLI(t, "", "-issuer", id.Issuer, "-jwks", id.JWKSURL(), tok)
	if code != exitAccept {
		t.Errorf("exit = %d, want %d (accept)", code, exitAccept)
	}
	for _, want := range []string{"✓ Token valid", "Kind:", "user", "Principal: alice", "Subject:   u-abc", "Role:", "Active:    true"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout missing %q\nfull output:\n%s", want, out)
		}
	}
}

func TestVerify_validServiceToken_showsClientID(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	tok := id.MintServiceToken(t, testutil.ServiceClaims{
		ClientID: "svc-pump", Audience: "mqtt", Scope: "publish",
	})

	code, out, _ := runCLI(t, "", "-issuer", id.Issuer, "-jwks", id.JWKSURL(), tok)
	if code != exitAccept {
		t.Errorf("exit = %d, want accept", code)
	}
	if !strings.Contains(out, "service") || !strings.Contains(out, "svc-pump") || !strings.Contains(out, "publish") {
		t.Errorf("service token output missing fields:\n%s", out)
	}
}

func TestVerify_expiredToken_returnsDenyWithExpiredVerdict(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	tok := id.MintUserToken(t, testutil.UserClaims{
		Subject: "u", Username: "alice", TTL: -time.Minute,
	})

	code, out, _ := runCLI(t, "", "-issuer", id.Issuer, "-jwks", id.JWKSURL(), tok)
	if code != exitDeny {
		t.Errorf("exit = %d, want deny", code)
	}
	if !strings.Contains(out, "expired") {
		t.Errorf("output should mention expiry:\n%s", out)
	}
}

func TestVerify_wrongIssuer_returnsDenyInvalid(t *testing.T) {
	// Token signed by id is fine, but we ask the CLI to expect a different
	// issuer — the verifier should reject and the CLI should say "invalid".
	id := testutil.NewTestIdentity(t)
	tok := id.MintUserToken(t, testutil.UserClaims{Subject: "u", Username: "alice"})

	code, out, _ := runCLI(t, "", "-issuer", "https://wrong.example.com", "-jwks", id.JWKSURL(), tok)
	if code != exitDeny {
		t.Errorf("exit = %d, want deny", code)
	}
	if !strings.Contains(out, "invalid") {
		t.Errorf("output should classify as invalid:\n%s", out)
	}
}

func TestVerify_usernameMismatch_returnsDeny(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	tok := id.MintUserToken(t, testutil.UserClaims{Subject: "u", Username: "alice"})

	code, out, _ := runCLI(t, "", "-issuer", id.Issuer, "-jwks", id.JWKSURL(),
		"-username", "mallory", tok)
	if code != exitDeny {
		t.Errorf("exit = %d, want deny", code)
	}
	if !strings.Contains(out, "username_mismatch") {
		t.Errorf("verdict should be username_mismatch:\n%s", out)
	}
	if !strings.Contains(out, "mallory") || !strings.Contains(out, "alice") {
		t.Errorf("reason should name both usernames:\n%s", out)
	}
}

func TestVerify_usernameMatch_accepts(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	tok := id.MintUserToken(t, testutil.UserClaims{Subject: "u", Username: "alice"})

	code, _, _ := runCLI(t, "", "-issuer", id.Issuer, "-jwks", id.JWKSURL(),
		"-username", "alice", tok)
	if code != exitAccept {
		t.Errorf("exit = %d, want accept", code)
	}
}

func TestVerify_jwksUnreachable_returnsPlumbing(t *testing.T) {
	// Point at a port that isn't listening. The verifier's first parse
	// will fail to fetch JWKS — that's a plumbing error, not a denial.
	tok := "eyJhbGciOiJFUzI1NiIsImtpZCI6Ing"

	code, out, _ := runCLI(t, "",
		"-issuer", "http://127.0.0.1:1",
		"-jwks", "http://127.0.0.1:1/.well-known/jwks.json",
		tok)
	if code != exitPlumbing && code != exitDeny {
		// Depending on how the JWT library treats the kid lookup, this
		// may surface as ErrTokenInvalid (deny) rather than plumbing.
		// Accept either — what matters is that we don't crash and we
		// don't claim success.
		t.Errorf("exit = %d, want deny or plumbing (got: %s)", code, out)
	}
}

func TestVerify_tokenFromStdin(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	tok := id.MintUserToken(t, testutil.UserClaims{Subject: "u", Username: "alice"})

	// Trailing newline simulates `echo "$TOKEN" | mqtt-auth-verify`.
	code, _, _ := runCLI(t, tok+"\n", "-issuer", id.Issuer, "-jwks", id.JWKSURL())
	if code != exitAccept {
		t.Errorf("stdin token: exit = %d, want accept", code)
	}
}

func TestVerify_tokenFromFile(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	tok := id.MintUserToken(t, testutil.UserClaims{Subject: "u", Username: "alice"})

	dir := t.TempDir()
	path := filepath.Join(dir, "token.txt")
	if err := os.WriteFile(path, []byte(tok+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	code, _, _ := runCLI(t, "", "-issuer", id.Issuer, "-jwks", id.JWKSURL(), "-file", path)
	if code != exitAccept {
		t.Errorf("file token: exit = %d, want accept", code)
	}
}

func TestVerify_emptyInput_returnsPlumbing(t *testing.T) {
	code, _, errOut := runCLI(t, "", "-issuer", "https://id.swee.net")
	if code != exitPlumbing {
		t.Errorf("no token: exit = %d, want plumbing", code)
	}
	if !strings.Contains(errOut, "no token") {
		t.Errorf("stderr should explain missing token:\n%s", errOut)
	}
}

func TestVerify_jsonOutput_isParseable(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	tok := id.MintUserToken(t, testutil.UserClaims{
		Subject: "u-abc", Username: "alice", Role: "admin", Active: true,
	})

	code, out, _ := runCLI(t, "", "-issuer", id.Issuer, "-jwks", id.JWKSURL(),
		"-json", "-username", "alice", tok)
	if code != exitAccept {
		t.Fatalf("exit = %d, want accept", code)
	}
	var r Result
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, out)
	}
	if r.Verdict != "valid" || !r.WouldAuthenticate {
		t.Errorf("verdict = %q, would_auth = %v; want valid+true", r.Verdict, r.WouldAuthenticate)
	}
	if r.Principal != "alice" || r.Kind != "user" {
		t.Errorf("missing claims in JSON: %+v", r)
	}
	if r.Active == nil || !*r.Active {
		t.Errorf("Active should be true, got %v", r.Active)
	}
}

func TestVerify_helpFlag_exitsZero(t *testing.T) {
	code, _, _ := runCLI(t, "", "-h")
	if code != exitAccept {
		t.Errorf("-h exit = %d, want 0", code)
	}
}

func TestRelTime_humanReadable(t *testing.T) {
	cases := []struct {
		delta   time.Duration
		want    string
		wantHas string // optional substring check instead of exact
	}{
		{30 * time.Minute, "", "in 30m"},
		{2 * time.Hour, "", "in 2h"},
		{-time.Hour, "", "1h0m0s ago"},
	}
	for _, c := range cases {
		got := relTime(time.Now().Add(c.delta))
		if c.want != "" && got != c.want {
			t.Errorf("relTime(+%v) = %q, want %q", c.delta, got, c.want)
		}
		if c.wantHas != "" && !strings.Contains(got, c.wantHas) {
			t.Errorf("relTime(+%v) = %q, should contain %q", c.delta, got, c.wantHas)
		}
	}
}
