# mqtt-auth

A Mosquitto MQTT broker authentication plugin that validates JWTs issued by
[identity](https://github.com/sweeney/identity) (id.swee.net).

Mosquitto loads this plugin as a `.so` (cgo) and calls into Go for every
authentication and ACL check. The Go core is the real implementation; the C
glue is a thin bridge to mosquitto's plugin API (v4, supported by mosquitto
2.0.21).

## Install

On Debian/Ubuntu with mosquitto already installed:

```bash
# Pinned tag:
curl -fsSL https://github.com/sweeney/mqtt-auth/releases/download/v0.1.0/mqtt-auth_0.1.0_amd64.deb -o /tmp/mqtt-auth.deb
sudo apt install /tmp/mqtt-auth.deb

# Or via the convenience installer:
curl -fsSL https://github.com/sweeney/mqtt-auth/releases/latest/download/install.sh | sh
```

The package drops:

- `/usr/lib/mosquitto/plugins/mqtt-auth.so`
- `/usr/bin/mqtt-auth-verify`
- `/etc/mosquitto/conf.d/10-mqtt-auth.conf` *(conffile — your edits survive upgrades)*
- `/usr/share/doc/mqtt-auth/production.mosquitto.conf`

Postinst runs `systemctl try-restart mosquitto` so the plugin takes effect.

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

## Build from source

```bash
sudo apt install mosquitto-dev libmosquitto-dev gettext-base   # plugin headers + envsubst
go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.41.0      # only needed for `make package`

make plugin                       # bin/mqtt-auth.so
make verify                       # bin/mqtt-auth-verify
make package VERSION=0.1.0        # dist/mqtt-auth_0.1.0_amd64.deb
```

## Debug a token

`mqtt-auth-verify` reproduces the plugin's verdict outside the broker — useful
when a client is being refused and you want to know why.

```bash
echo "$JWT" | bin/mqtt-auth-verify
bin/mqtt-auth-verify -username alice "$JWT"
bin/mqtt-auth-verify -json -file /tmp/token | jq
```

Exit codes: `0` accept, `1` deny, `2` plumbing (JWKS unreachable etc.).

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
