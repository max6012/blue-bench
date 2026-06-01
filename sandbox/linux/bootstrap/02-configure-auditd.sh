#!/usr/bin/env bash
# Configure auditd with the sandbox audit ruleset.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "ABORT: must run as root." >&2
    exit 1
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
CONFIG_DIR="$(cd "$HERE/../config" && pwd)"

# Install the rules.
install -m 0640 -o root -g root "$CONFIG_DIR/audit.rules" /etc/audit/rules.d/sandbox.rules

# Set logfile size + retention so a long technique doesn't blow the
# logfile mid-run.
sed -i \
    -e 's|^max_log_file = .*|max_log_file = 256|' \
    -e 's|^num_logs = .*|num_logs = 5|' \
    -e 's|^max_log_file_action = .*|max_log_file_action = ROTATE|' \
    /etc/audit/auditd.conf

# Apply rules + restart.
augenrules --load
systemctl enable auditd
systemctl restart auditd

# Verify a sample rule loaded.
if ! auditctl -l | grep -q 'execve'; then
    echo "ABORT: execve rule not loaded by auditd." >&2
    exit 1
fi

echo "OK: auditd configured + running."
