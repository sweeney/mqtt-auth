// Command mqtt-auth-verify validates a JWT exactly the way the mosquitto
// auth plugin would, and prints why it would or wouldn't accept a CONNECT.
//
// Pipe a token in on stdin, pass a path with -file, or hand it as the
// first positional argument:
//
//	echo "$TOKEN" | mqtt-auth-verify
//	mqtt-auth-verify -file /tmp/tok
//	mqtt-auth-verify "$TOKEN"
//
// To check username binding the way the plugin enforces it, add -username:
//
//	mqtt-auth-verify -username alice "$TOKEN"
//
// Exit codes:
//
//	0  token verifies (and, if -username given, the binding matches)
//	1  clean denial: expired, invalid signature, wrong issuer, username
//	   mismatch — the broker would refuse this CONNECT
//	2  plumbing failure: JWKS unreachable, bad flags — operator action needed
package main

import (
	"context"
	"os"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
