# Linux VM specification

## VM properties

| Field | Value |
|---|---|
| Hypervisor | UTM (Apple hypervisor.framework) |
| Architecture | x86_64 (matches Windows VM; cleaner cross-VM tooling) |
| OS | Ubuntu Server 22.04 LTS, minimal install |
| vCPU | 2 |
| RAM | 4 GB |
| Disk | 30 GB qcow2, thin-provisioned |
| Network | `sandbox-net` only (host-only, no NAT, no en0 bridge) |
| Static IP | `192.168.66.20/24`, no default gateway |
| DNS | `127.0.0.1` (no public resolver) |
| Snapshot | UTM snapshot named `baseline` after bootstrap |

## OOBE choices

- Locale: `en_US.UTF-8`
- Hostname: `sandbox-lnx`
- Username: `analyst`
- Password: any 12+ char value (local password manager) — not used
  by the orchestrator after key push
- OpenSSH server: install at OOBE time (Ubuntu installer's checkbox)
- Snap: skip if the installer offers it; bootstrap removes snap if
  it's already there
- Disk: ext4, full disk, no encryption (avoids LUKS-passphrase
  prompts on snapshot restore)

## Post-install verification

Before running `bootstrap.sh`, confirm:

```bash
ip -4 addr show enp0s2  # should show 192.168.66.20/24 only
ip route                # should NOT show a default route
ping -W 2 -c 1 8.8.8.8                  # must fail
ping -W 2 -c 1 192.168.66.10            # must succeed (Windows VM)
nslookup google.com 1.1.1.1             # must fail
```

If any "must fail" check passes, fix isolation before running the
bootstrap.

## Bootstrap deps (staged out-of-band)

The Linux VM has no internet egress, so the bootstrap relies on
packages pre-staged into `/tmp/sandbox-deps/`. From an internet-
connected host, download:

- Zeek 6.x .deb package (or build artefacts; see
  https://zeek.org/get-zeek/)
- Suricata 7.x .deb package (Ubuntu PPA mirror; static copy)
- The Atomic Red Team Linux runner (bash) repo zip
- Suricata-update rules tarball (or a pinned rules set)

Drop them in `/tmp/sandbox-deps/` and run `bootstrap.sh`.

Alternative: bake a one-time-use baseline VM image WITH internet
access during initial provisioning, install all the packages from
upstream apt repositories, then snapshot + permanently switch to
sandbox-net. This is faster than staging .debs manually if you accept
that the provisioning environment briefly has internet.
