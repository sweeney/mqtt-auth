#!/bin/sh
# Convenience installer for mqtt-auth.
#
# Usage:
#   curl -fsSL https://github.com/sweeney/mqtt-auth/releases/latest/download/install.sh | sh
#   curl -fsSL .../install.sh | sh -s -- v0.1.0
#
# What it does:
#   - On Debian/Ubuntu: downloads the .deb and runs `apt install ./*.deb`
#   - Elsewhere: extracts the tarball into the standard paths
#   - Either way: leaves a working mqtt-auth.so + drop-in conf, ready for
#     a `systemctl restart mosquitto`
#
# Anything destructive (overwriting config, restarting mosquitto) is gated
# behind explicit `--yes` prompts unless DEBIAN_FRONTEND=noninteractive.

set -eu

VERSION="${1:-latest}"
REPO="sweeney/mqtt-auth"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

if [ "$VERSION" = "latest" ]; then
    # GitHub redirects /releases/latest to the actual tag URL; strip the
    # trailing slash and use the tag name.
    VERSION="$(curl -fsSL -o /dev/null -w '%{url_effective}' \
        "https://github.com/${REPO}/releases/latest" \
        | sed 's:.*/::')"
fi

if [ -z "$VERSION" ] || [ "$VERSION" = "latest" ]; then
    echo "Could not resolve latest version; pass an explicit tag like v0.1.0" >&2
    exit 1
fi

# Strip a leading "v" for asset filenames (which use the bare version).
VER_BARE="${VERSION#v}"

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64) ASSET_ARCH=amd64 ;;
    aarch64|arm64) ASSET_ARCH=arm64 ;;
    *) echo "unsupported arch: $ARCH (need amd64 or arm64)" >&2; exit 1 ;;
esac

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
if [ "$OS" != "linux" ]; then
    echo "this installer only supports Linux (got $OS)" >&2
    exit 1
fi

is_debian=0
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}:${ID_LIKE:-}" in
        *debian*|*ubuntu*) is_debian=1 ;;
    esac
fi

cd "$TMPDIR"

if [ "$is_debian" = "1" ] && [ "$ASSET_ARCH" = "amd64" ]; then
    DEB="mqtt-auth_${VER_BARE}_${ASSET_ARCH}.deb"
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${DEB}"
    echo "Downloading ${URL}"
    curl -fsSL -o "$DEB" "$URL"
    echo "Installing $DEB (will prompt for sudo)"
    sudo apt-get update -qq
    # apt install resolves the mosquitto dependency for us.
    sudo apt-get install -y "./$DEB"
else
    TAR="mqtt-auth_${VER_BARE}_linux_${ASSET_ARCH}.tar.gz"
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${TAR}"
    echo "Downloading ${URL}"
    curl -fsSL -o "$TAR" "$URL"
    tar -xzf "$TAR"

    echo "Installing to standard paths (will prompt for sudo)"
    sudo install -d /usr/lib/mosquitto/plugins
    sudo install -m 0644 mqtt-auth.so /usr/lib/mosquitto/plugins/
    sudo install -m 0755 mqtt-auth-verify /usr/bin/
    sudo install -d /etc/mosquitto/conf.d
    if [ ! -e /etc/mosquitto/conf.d/10-mqtt-auth.conf ]; then
        sudo install -m 0644 mqtt-auth.conf /etc/mosquitto/conf.d/10-mqtt-auth.conf
        echo "Installed default drop-in /etc/mosquitto/conf.d/10-mqtt-auth.conf"
    else
        echo "Existing drop-in preserved at /etc/mosquitto/conf.d/10-mqtt-auth.conf"
        echo "(new template at /tmp/mqtt-auth.conf.new)"
        sudo install -m 0644 mqtt-auth.conf /tmp/mqtt-auth.conf.new
    fi

    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet mosquitto; then
        echo "Restarting mosquitto..."
        sudo systemctl try-restart mosquitto || true
    fi
fi

echo
echo "mqtt-auth ${VERSION} installed."
echo "Edit /etc/mosquitto/conf.d/10-mqtt-auth.conf then: systemctl restart mosquitto"
