#!/bin/sh
# Post-install hook for the mqtt-auth Debian package.
#
# Tries to restart mosquitto so the plugin takes effect, but never fails
# the install: in containers, CI runners, or partially-set-up systems
# systemctl behaviour is unpredictable, and we'd rather print a hint to
# the operator than break their apt install.

# Note: no `set -e` — every command here is allowed to fail.

if command -v systemctl >/dev/null 2>&1; then
    active=$(systemctl is-active mosquitto 2>/dev/null || true)
    if [ "$active" = "active" ]; then
        echo "mqtt-auth: restarting mosquitto so the plugin takes effect..."
        systemctl try-restart mosquitto 2>/dev/null || \
            echo "mqtt-auth: warning: failed to restart mosquitto; restart it manually"
    else
        echo "mqtt-auth: mosquitto is not currently active — start it when ready."
    fi
fi

cat <<'EOF'

mqtt-auth installed.

  Plugin:       /usr/lib/mosquitto/plugins/mqtt-auth.so
  Drop-in conf: /etc/mosquitto/conf.d/10-mqtt-auth.conf
  CLI:          /usr/bin/mqtt-auth-verify

Edit the drop-in conf to point at your identity service, then:

  systemctl restart mosquitto

To debug a token outside the broker:

  echo "$JWT" | mqtt-auth-verify -username alice

EOF

exit 0
