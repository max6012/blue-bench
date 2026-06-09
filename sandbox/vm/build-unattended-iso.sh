#!/usr/bin/env bash
# Build a small autounattend.iso that Windows Setup auto-discovers
# alongside the install ISO under QEMU.
#
# Approach: don't repack the upstream Win11 ISO. Produce a separate
# tiny ISO containing just autounattend.xml at its root, then attach
# both ISOs to the QEMU VM. Windows Setup scans all attached drives
# for autounattend.xml at the root and uses the first one found.
#
# This avoids the brittle UEFI-bootable Windows-ISO repack flow and
# keeps the upstream ISO untouched (so re-downloads are wasted only
# when Microsoft rolls a new build, not every time we tweak the
# unattend).
#
# Output: sandbox/vm/autounattend.iso (~150 KB).

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/autounattend.xml"
OUT="$HERE/autounattend.iso"

if [[ ! -f $SRC ]]; then
    echo "ABORT: $SRC not found." >&2
    exit 1
fi

# Stage the file in a temp dir; hdiutil builds the ISO from a
# directory tree, so we need autounattend.xml as the SOLE root
# entry to keep Windows Setup's auto-detection unambiguous.
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
cp "$SRC" "$stage/autounattend.xml"

# hdiutil makehybrid refuses to overwrite -- always start clean so
# the script is rerunnable after autounattend.xml edits.
rm -f "$OUT"

# hdiutil is built into macOS. -joliet keeps long-filename
# compatibility; the volume name AUTOUNATTEND matches the label
# Windows Setup expects when scanning for unattend sources.
hdiutil makehybrid \
    -iso -joliet \
    -default-volume-name AUTOUNATTEND \
    -o "$OUT" \
    "$stage"

echo "OK: built $OUT ($(stat -f%z "$OUT") bytes)"
echo "Attach to QEMU as a second cdrom: -drive file=$OUT,media=cdrom,if=virtio"
