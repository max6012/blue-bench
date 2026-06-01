#!/usr/bin/env bash
# Install Linux VM packages: auditd, Zeek, Suricata, prerequisites.
#
# Assumes packages are either reachable via apt (provisioning has temp
# internet) or staged into /tmp/sandbox-deps/ as .deb files. The script
# tries apt first; if apt fails (no egress), falls back to dpkg -i on
# the staged .debs.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "ABORT: 01-install-packages.sh must run as root (use sudo)." >&2
    exit 1
fi

STAGED=/tmp/sandbox-deps
PKGS=(
    auditd
    audispd-plugins
    zeek
    suricata
    suricata-update
    jq
    openssh-server
    rsync
    curl
    git
    python3
    python3-pip
)

apt_ok=0
if apt-get update -y >/tmp/apt-update.log 2>&1; then
    if apt-get install -y --no-install-recommends "${PKGS[@]}" >/tmp/apt-install.log 2>&1; then
        apt_ok=1
        echo "OK: packages installed via apt."
    fi
fi

if [[ $apt_ok -eq 0 ]]; then
    echo "apt unavailable; falling back to staged .deb files in $STAGED"
    if [[ ! -d $STAGED ]]; then
        echo "ABORT: $STAGED missing; nothing to install from." >&2
        echo "Either (a) restore VM internet briefly + apt-get update," >&2
        echo "or (b) stage .deb files into $STAGED before running." >&2
        exit 1
    fi
    dpkg -i "$STAGED"/*.deb || true   # may have dep order issues
    apt-get install -f -y --no-install-recommends || true
    dpkg -i "$STAGED"/*.deb            # second pass with deps resolved
fi

# Remove snap if present (noise + unnecessary on a single-purpose VM).
if command -v snap >/dev/null 2>&1; then
    systemctl stop snapd 2>/dev/null || true
    systemctl disable snapd 2>/dev/null || true
    apt-get purge -y snapd >/dev/null 2>&1 || true
fi

# Verify each package is present.
for cmd in auditctl zeek suricata jq; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ABORT: $cmd not found on PATH after install." >&2
        exit 1
    fi
done

echo "OK: packages present (auditd, zeek, suricata, jq, openssh-server, etc.)."
