#!/usr/bin/env bash
# Configure Zeek to listen on the sandbox-net interface (enp0s2).

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "ABORT: must run as root." >&2
    exit 1
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
CONFIG_DIR="$(cd "$HERE/../config" && pwd)"

# Distro layout varies between source-install and apt-package; try
# both common roots.
for root in /opt/zeek /usr/local/zeek /usr; do
    if [[ -x "$root/bin/zeek" ]]; then
        ZEEK_ROOT="$root"
        break
    fi
done

if [[ -z "${ZEEK_ROOT:-}" ]]; then
    echo "ABORT: zeek binary not found in any of /opt/zeek, /usr/local/zeek, /usr" >&2
    exit 1
fi

echo "Zeek root: $ZEEK_ROOT"

# Find the site/ and etc/ paths.
SITE_DIR="$ZEEK_ROOT/share/zeek/site"
ETC_DIR="$ZEEK_ROOT/etc"
if [[ ! -d $SITE_DIR ]]; then
    SITE_DIR=$(find "$ZEEK_ROOT" -type d -name site 2>/dev/null | head -1)
fi
if [[ ! -d $ETC_DIR ]]; then
    ETC_DIR=$(find "$ZEEK_ROOT" -type d -name etc 2>/dev/null | head -1)
fi

install -m 0644 "$CONFIG_DIR/zeek-site-local.zeek" "$SITE_DIR/local.zeek"

# node.cfg: single standalone worker on enp0s2.
cat > "$ETC_DIR/node.cfg" <<EOF
[zeek]
type=standalone
host=localhost
interface=enp0s2
EOF

# networks.cfg: declare the sandbox subnet as local.
cat > "$ETC_DIR/networks.cfg" <<EOF
192.168.66.0/24 sandbox-net
EOF

# Deploy + start.
ZEEKCTL="$ZEEK_ROOT/bin/zeekctl"
if [[ -x $ZEEKCTL ]]; then
    "$ZEEKCTL" deploy
    "$ZEEKCTL" status || true
else
    echo "WARN: zeekctl not found at $ZEEKCTL -- you may need to start zeek manually."
fi

# Verify zeek is running.
if pgrep -x zeek >/dev/null 2>&1; then
    echo "OK: Zeek running."
else
    echo "WARN: Zeek process not detected. Check $ZEEK_ROOT/logs/current/."
fi
