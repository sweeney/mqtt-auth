#!/bin/sh
# Pre-remove hook for the mqtt-auth Debian package.
#
# We deliberately do NOT modify mosquitto's main configuration. The drop-in
# under /etc/mosquitto/conf.d/ will be removed by dpkg, which means on the
# next mosquitto restart the broker will run without our plugin loaded —
# and because allow_anonymous=false was set by our drop-in, anonymous
# connections will also revert to mosquitto's default (which is anonymous
# allow=false in mosquitto 2.0+ — i.e., nobody can connect).
#
# That's deliberate: better to refuse all connects than to silently allow
# anonymous because someone uninstalled the auth package.

set -e

cat <<'EOF'

mqtt-auth is being removed.

The drop-in /etc/mosquitto/conf.d/10-mqtt-auth.conf will be removed by dpkg.
After this, mosquitto will no longer load the plugin — restart it to apply:

  systemctl restart mosquitto

Note: mosquitto 2.0 defaults to refusing anonymous connections, so unless
you have other auth configured, the broker will reject every CONNECT after
this package is removed. Configure replacement auth before removing in
production.

EOF

exit 0
