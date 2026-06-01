#!/usr/bin/env bash
# Install the Atomic Red Team Linux runner.
#
# Linux ART techniques are bash scripts in the redcanaryco/atomic-red-team
# repo (same repo as Windows; the per-technique YAML carries OS-specific
# blocks). The runner is invoked via the same Invoke-AtomicTest module
# under PowerShell on Linux (pwsh).

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "ABORT: must run as root." >&2
    exit 1
fi

STAGED=/tmp/sandbox-deps
ART_ROOT=/opt/atomic-red-team
ART_ZIP="$STAGED/atomic-red-team.zip"
PWSH_DEB="$STAGED/powershell.deb"

if [[ ! -f $ART_ZIP ]]; then
    echo "ABORT: $ART_ZIP missing." >&2
    echo "Stage atomic-red-team.zip into $STAGED before running this script." >&2
    exit 1
fi

# Install PowerShell (pwsh) on Linux -- needed to run Invoke-AtomicTest.
if ! command -v pwsh >/dev/null 2>&1; then
    if [[ -f $PWSH_DEB ]]; then
        dpkg -i "$PWSH_DEB" || apt-get install -f -y --no-install-recommends
    else
        # Try apt; tolerate failure if no egress.
        apt-get install -y --no-install-recommends powershell || {
            echo "ABORT: pwsh not installable; stage $PWSH_DEB or restore apt egress." >&2
            exit 1
        }
    fi
fi

# Unzip ART repo.
mkdir -p "$ART_ROOT"
if [[ ! -d "$ART_ROOT/atomics" ]]; then
    unzip -q "$ART_ZIP" -d "$ART_ROOT"
    # Normalise: collapse top-level "atomic-red-team-master" if present.
    if [[ ! -d "$ART_ROOT/atomics" ]]; then
        nested=$(find "$ART_ROOT" -maxdepth 2 -type d -name atomics 2>/dev/null | head -1)
        if [[ -n $nested ]]; then
            mv "$nested" "$ART_ROOT/atomics"
        fi
    fi
fi

# Same for the Invoke-AtomicRedTeam module (PowerShell-side).
IAR_ZIP="$STAGED/invoke-atomicredteam.zip"
IAR_ROOT="$ART_ROOT/invoke-atomicredteam"
if [[ ! -f $IAR_ZIP ]]; then
    echo "ABORT: $IAR_ZIP missing." >&2
    exit 1
fi
if [[ ! -f "$IAR_ROOT/Invoke-AtomicRedTeam.psd1" ]]; then
    unzip -q "$IAR_ZIP" -d "$ART_ROOT"
    nested=$(find "$ART_ROOT" -maxdepth 2 -type d -name 'invoke*' 2>/dev/null | head -1)
    if [[ -n $nested && $nested != "$IAR_ROOT" ]]; then
        mv "$nested" "$IAR_ROOT"
    fi
fi

# Set the PSAtomicsFolder env var globally.
echo "PSAtomicsFolder=$ART_ROOT/atomics" > /etc/environment.d/50-art.conf
# /etc/environment for shells that don't read environment.d:
if ! grep -q PSAtomicsFolder /etc/environment 2>/dev/null; then
    echo "PSAtomicsFolder=$ART_ROOT/atomics" >> /etc/environment
fi

# Smoke-test that pwsh can import the module.
pwsh -NoProfile -Command \
    "Import-Module '$IAR_ROOT/Invoke-AtomicRedTeam.psd1' -Force; Get-Command Invoke-AtomicTest | Out-Null"

echo "OK: Atomic Red Team Linux runner installed at $ART_ROOT."
