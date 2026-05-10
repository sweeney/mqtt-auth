# mqtt-auth

A Mosquitto MQTT broker authentication plugin that validates JWTs issued by
[identity](https://github.com/sweeney/identity) (id.swee.net).

Mosquitto loads this plugin as a `.so` (cgo) and calls into Go for every
authentication and ACL check. The Go core is the real implementation; the C
glue is a thin bridge to mosquitto's plugin API (v4, supported by mosquitto
2.0.21).

## Status

v1: JWT verification only. ACL checks return allow; topic-level authorisation
will be added in a follow-up.

## How it works

On `CONNECT`, mosquitto passes the username and password fields to the plugin.
This plugin treats the password as a JWT signed by id.swee.net (ES256), looks
up the verifying public key from the cached JWKS at
`{issuer}/.well-known/jwks.json`, and accepts the connection if the signature,
issuer, and expiry all check out — and the MQTT username matches the token's
principal (`usr` for user tokens, `client_id` for service tokens, RFC 9068).

JWKS is cached in-memory for 5 minutes by default. Key rotations are picked up
automatically on the next `kid` miss.

## Build

```bash
sudo apt install libmosquitto-dev   # provides mosquitto_plugin.h
make plugin                          # produces bin/mqtt-auth.so
```

## Configure mosquitto

```
auth_plugin /etc/mosquitto/plugins/mqtt-auth.so
auth_opt_jwt_issuer https://id.swee.net
auth_opt_jwt_jwks_url https://id.swee.net/.well-known/jwks.json
auth_opt_jwt_jwks_cache_ttl 5m
auth_opt_require_username_match true
```

## Tests

```bash
make test            # unit tests
make test-race       # unit tests with -race
make cover           # coverage report
make e2e             # end-to-end against a real mosquitto broker
```
