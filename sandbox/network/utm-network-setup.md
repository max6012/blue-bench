# UTM internal network setup

One-time UTM-level configuration that puts both sandbox VMs on an
isolated virtual switch with no path to the Mac host network or the
public internet.

## Step 1 — create the host-only network

UTM 4.5+ supports "Host Only" network mode at the VM level, but the
underlying virtual switch is shared. Create the named switch by
attaching the first VM to a host-only network and renaming the
network in UTM > Settings > Network.

Recommended subnet: `192.168.66.0/24` (any RFC1918 /24 that doesn't
collide with your Mac's en0 subnet). Gateway/DHCP can be left at UTM
defaults; we will pin static IPs inside the VMs to avoid drift.

## Step 2 — pin static IPs

Disable DHCP inside both VMs (or leave DHCP on but reserve the same
addresses every boot — your call):

- Windows VM: `192.168.66.10/24`, default gateway `none`, DNS `127.0.0.1`
- Linux VM:   `192.168.66.20/24`, default gateway `none`, DNS `127.0.0.1`

`default gateway = none` is the load-bearing safe-fire control. Without
a default route, the VM cannot egress to anything outside `192.168.66.0/24`.

## Step 3 — Mac-side pfctl rule (defence in depth)

UTM's host-only mode is supposed to be isolated, but a misconfigured
en0 bridge could leak. Add a pfctl rule on the Mac to drop any pkt
sourced from the sandbox subnet:

```bash
sudo tee -a /etc/pf.conf <<'EOF'
# blue-bench sandbox safe-fire
block drop from 192.168.66.0/24 to any
block drop to 192.168.66.0/24 from any out
EOF
sudo pfctl -f /etc/pf.conf
sudo pfctl -e
```

The `out` rule on the second line prevents the Mac from initiating
traffic to the sandbox subnet either; that means **the orchestrator
scripts (which need to SSH into the VMs) cannot run while the pfctl
rules are enabled**.

The right workflow is:
1. Disable pfctl rules before a sandbox run (`sudo pfctl -d`)
2. Run the atomic + harvest
3. Re-enable pfctl rules (`sudo pfctl -e`) when done

`orchestrator/safe-fire-check.sh` verifies the rules are loaded and
warns if they're currently disabled.

## Step 4 — verify isolation

From inside each VM after bootstrap:

```bash
# Linux VM
ping -W 2 -c 1 8.8.8.8     # must fail
ping -W 2 -c 1 192.168.66.10  # must succeed (the other VM)
nslookup google.com 1.1.1.1   # must fail
```

```powershell
# Windows VM
Test-NetConnection 8.8.8.8 -Port 53            # must fail
Test-NetConnection 192.168.66.20 -Port 22      # must succeed
Resolve-DnsName google.com -Server 1.1.1.1     # must fail
```

The expected pattern: **VM ↔ VM works, VM ↔ anything outside fails.**
If any of the "must fail" probes succeeds, do not run atomics — debug
the network isolation first.

## Why not Docker

`dockurr/windows`-style approaches need `/dev/kvm`, which Docker
Desktop on macOS does not provide. UTM uses Apple's hypervisor.framework
directly and is Mac-native. The sandbox is single-tenant single-shot
work; the container-orchestration overhead Docker would add is wasted
for this use case.
