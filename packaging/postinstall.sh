#!/bin/sh
# Post-install hook for the mqtt-auth Debian package.
#
# Restarts mosquitto so the plugin takes effect. Uses try-restart so:
#   - if mosquitto isn't running, nothing happens (operator may not have
#     started it yet)
#   - if it is running, it's restarted in-place
#
# Failures are tolerated: in containers or sysvinit systems systemctl may
# not be present, and we don't want the install to abort.

set -e

if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet mosquitto 2>/dev/null; then
        echo "mqtt-auth: restarting mosquitto so the plugin takes effect..."
        systemctl try-restart mosquitto || \
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
