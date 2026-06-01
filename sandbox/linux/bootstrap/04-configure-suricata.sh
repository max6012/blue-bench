#!/usr/bin/env bash
# Configure Suricata to listen on the sandbox-net tap.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "ABORT: must run as root." >&2
    exit 1
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
CONFIG_DIR="$(cd "$HERE/../config" && pwd)"

# Install the config.
install -m 0644 "$CONFIG_DIR/suricata.yaml" /etc/suricata/suricata.yaml

# Ensure rule directory exists; if no rules are present, write a stub
# so Suricata starts cleanly without external rule fetch (sandbox has
# no egress).
mkdir -p /etc/suricata/rules
if [[ ! -f /etc/suricata/rules/suricata.rules ]] || \
   ! grep -q '^[^#]' /etc/suricata/rules/suricata.rules 2>/dev/null; then
    cat > /etc/suricata/rules/suricata.rules <<'EOF'
# Stub rule set for the sandbox: one always-fire alert per HOME_NET
# pkt so the eve.json alert channel is exercised and t-apt-inject's
# downstream parsing has examples to consume. This is intentionally
# noisy -- it is NOT a real detection ruleset.
alert tcp $HOME_NET any -> $HOME_NET any (msg:"SANDBOX-MARKER: tcp flow inside sandbox-net"; sid:1000001; rev:1;)
EOF
fi

# Validate config syntax first.
if ! suricata -T -c /etc/suricata/suricata.yaml -v 2>/tmp/suricata-test.log; then
    echo "ABORT: suricata -T validation failed; see /tmp/suricata-test.log" >&2
    cat /tmp/suricata-test.log
    exit 1
fi

# Enable + start.
systemctl enable suricata
systemctl restart suricata

# Tiny smoke wait so the service has a chance to bind the interface.
sleep 3

if ! pgrep -x suricata >/dev/null 2>&1; then
    echo "ABORT: Suricata process not running after restart." >&2
    systemctl status suricata --no-pager || true
    exit 1
fi

echo "OK: Suricata running on enp0s2; eve.json under /var/log/suricata/eve.json"
