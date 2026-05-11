//go:build e2e

// Package e2e runs the auth plugin inside a real mosquitto broker against a
// stub identity service, then exercises CONNECT outcomes with a paho client.
//
// Skipped by default (build tag "e2e"). To run locally:
//
//	make plugin
//	go test -tags=e2e ./test/e2e/...
//
// CI installs mosquitto and runs this in its own job. The harness:
//
//  1. starts a TestIdentity (httptest JWKS server + token minter)
//  2. writes a mosquitto.conf in a temp dir, loading bin/mqtt-auth.so and
//     pointing auth_opt_jwt_issuer / auth_opt_jwt_jwks_url at the stub
//  3. launches mosquitto on a random port, waits for the listener
//  4. connects with paho and asserts CONNECT accept/reject per scenario
package e2e

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"

	"github.com/sweeney/mqtt-auth/internal/auth/testutil"
)

// broker holds the per-test mosquitto process and config.
type broker struct {
	cmd    *exec.Cmd
	port   int
	logBuf *strings.Builder
}

// newBroker spawns mosquitto with our plugin loaded and the identity at the
// given URL. The plugin must already be built at the path computed in
// pluginPath().
func newBroker(t *testing.T, identityIssuer, jwksURL string) *broker {
	t.Helper()

	plugin := pluginPath(t)
	if _, err := os.Stat(plugin); err != nil {
		t.Fatalf("plugin not built at %s — run `make plugin` first: %v", plugin, err)
	}

	port := pickFreePort(t)
	dir := t.TempDir()
	confPath := filepath.Join(dir, "mosquitto.conf")
	logPath := filepath.Join(dir, "mosquitto.log")

	// per_listener_settings false: auth_plugin and auth_opt_* apply globally
	// (mosquitto 2.0 default). allow_anonymous false: every CONNECT must be
	// authenticated by our plugin.
	conf := fmt.Sprintf(`listener %d 127.0.0.1
allow_anonymous false
per_listener_settings false
log_type all
log_dest file %s
auth_plugin %s
auth_opt_jwt_issuer %s
auth_opt_jwt_jwks_url %s
auth_opt_require_username_match true
`, port, logPath, plugin, identityIssuer, jwksURL)

	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		t.Fatalf("write conf: %v", err)
	}

	cmd := exec.Command("mosquitto", "-c", confPath, "-v")
	logBuf := &strings.Builder{}
	cmd.Stdout = logBuf
	cmd.Stderr = logBuf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start mosquitto: %v", err)
	}

	b := &broker{cmd: cmd, port: port, logBuf: logBuf}
	t.Cleanup(func() { b.stop(t) })

	if err := waitListening("127.0.0.1", port, 5*time.Second); err != nil {
		t.Fatalf("broker not listening: %v\nlog:\n%s", err, b.logBuf.String())
	}
	return b
}

func (b *broker) addr() string { return fmt.Sprintf("tcp://127.0.0.1:%d", b.port) }

func (b *broker) stop(t *testing.T) {
	t.Helper()
	if b.cmd == nil || b.cmd.Process == nil {
		return
	}
	_ = b.cmd.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() { done <- b.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = b.cmd.Process.Kill()
		<-done
	}
}

// connect opens an MQTT connection with the given username/password and
// returns the resulting error from paho's connect Token. nil error = accepted.
func connect(t *testing.T, addr, clientID, user, pass string) error {
	t.Helper()
	opts := mqtt.NewClientOptions().
		AddBroker(addr).
		SetClientID(clientID).
		SetUsername(user).
		SetPassword(pass).
		SetConnectTimeout(2 * time.Second).
		SetConnectRetry(false).
		SetCleanSession(true)
	c := mqtt.NewClient(opts)
	tok := c.Connect()
	if !tok.WaitTimeout(3 * time.Second) {
		return fmt.Errorf("connect timed out")
	}
	if err := tok.Error(); err != nil {
		return err
	}
	c.Disconnect(100)
	return nil
}

// TestE2E_validUserTokenIsAccepted is the happy path: a fresh user token whose
// usr claim matches the MQTT username should produce a successful CONNECT.
func TestE2E_validUserTokenIsAccepted(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	b := newBroker(t, id.Issuer, id.JWKSURL())

	tok := id.MintUserToken(t, testutil.UserClaims{
		Subject: "u-1", Username: "alice", Role: "user", Active: true,
	})
	if err := connect(t, b.addr(), "client-alice", "alice", tok); err != nil {
		t.Errorf("valid token rejected: %v\nbroker log:\n%s", err, b.logBuf.String())
	}
}

// TestE2E_validServiceTokenIsAccepted verifies that RFC 9068 service tokens
// also CONNECT through, with the MQTT username matching the client_id claim.
func TestE2E_validServiceTokenIsAccepted(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	b := newBroker(t, id.Issuer, id.JWKSURL())

	tok := id.MintServiceToken(t, testutil.ServiceClaims{
		ClientID: "svc-pump", Audience: "mqtt", Scope: "publish",
	})
	if err := connect(t, b.addr(), "client-pump", "svc-pump", tok); err != nil {
		t.Errorf("valid service token rejected: %v\nbroker log:\n%s", err, b.logBuf.String())
	}
}

// TestE2E_garbagePasswordIsRejected: anything that isn't a JWT must be denied.
func TestE2E_garbagePasswordIsRejected(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	b := newBroker(t, id.Issuer, id.JWKSURL())

	if err := connect(t, b.addr(), "client-bad", "alice", "not-a-jwt"); err == nil {
		t.Errorf("garbage password accepted")
	}
}

// TestE2E_usernameMismatchIsRejected: a valid token whose usr doesn't match
// the MQTT username is denied (defence against leaked-token impersonation).
func TestE2E_usernameMismatchIsRejected(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	b := newBroker(t, id.Issuer, id.JWKSURL())

	tok := id.MintUserToken(t, testutil.UserClaims{Subject: "u-1", Username: "alice"})
	if err := connect(t, b.addr(), "client-mallory", "mallory", tok); err == nil {
		t.Errorf("mismatched username accepted")
	}
}

// TestE2E_expiredTokenIsRejected: tokens past their exp must be denied.
func TestE2E_expiredTokenIsRejected(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	b := newBroker(t, id.Issuer, id.JWKSURL())

	tok := id.MintUserToken(t, testutil.UserClaims{
		Subject: "u-1", Username: "alice",
		TTL: -time.Second, // expired the moment it was minted
	})
	if err := connect(t, b.addr(), "client-stale", "alice", tok); err == nil {
		t.Errorf("expired token accepted")
	}
}

// TestE2E_anonymousIsRejected: no username/password at all should be denied —
// allow_anonymous is off and the plugin sees an empty password.
func TestE2E_anonymousIsRejected(t *testing.T) {
	id := testutil.NewTestIdentity(t)
	b := newBroker(t, id.Issuer, id.JWKSURL())

	if err := connect(t, b.addr(), "client-anon", "", ""); err == nil {
		t.Errorf("anonymous CONNECT accepted")
	}
}

// pluginPath resolves the absolute path to the built .so. Tests fail with a
// helpful message if the build hasn't been run.
func pluginPath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	// thisFile lives at test/e2e/e2e_test.go; repo root is two dirs up.
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	return filepath.Join(root, "bin", "mqtt-auth.so")
}

// pickFreePort returns an ephemeral port the OS lent us briefly; the listen
// is closed immediately so mosquitto can claim it. A race window exists but
// is negligible in practice.
func pickFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// waitListening polls until host:port accepts a TCP connection or the
// deadline passes. Returns the timeout reason on expiry.
func waitListening(host string, port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("port %d did not accept connections within %v", port, timeout)
}
