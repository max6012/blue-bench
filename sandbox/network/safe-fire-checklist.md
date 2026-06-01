# Safe-fire checklist

Run this checklist (or the automated `orchestrator/safe-fire-check.sh`)
before every atomic execution. Atomics are real attack code; the only
thing standing between them and an unintended target is the isolation
verified here.

## Pre-run gates (all must pass)

1. **UTM network**: both VMs attached to `sandbox-net` host-only
   network (not "Shared Network" or "Bridged").
2. **VM default route**: each VM's routing table has no default
   gateway (or its default gateway is unreachable).
3. **VM DNS**: each VM's DNS resolver is set to a non-public address
   (`127.0.0.1` or a non-existent stub). External DNS lookups must
   fail.
4. **Public-internet ICMP probe**: from each VM, `ping 8.8.8.8` fails
   with a timeout (not a "host unreachable", which would imply some
   route is being attempted).
5. **Cross-VM connectivity**: VMs can reach each other on the
   sandbox subnet. (If they can't, the tap won't see Windows traffic.)
6. **pfctl rules** (optional belt-and-suspenders): if enabled,
   `pfctl -s rules` shows the sandbox-net block-from / block-to
   rules. If running atomics, you need pfctl DISABLED for SSH to
   work; the orchestrator re-enables on exit.

## Post-run hygiene

1. **Snapshot revert**: after harvest, restore both VMs to the
   `baseline` snapshot. **Do not let an atomic-modified VM persist
   across runs** — Sysmon's own state, scheduled tasks, registry
   keys, and accounts from one technique can contaminate the next.
2. **Captured-data integrity**: every harvested `data/raw/sandbox/
   <run_id>/` directory must include `manifest.json` recording the
   exact technique, parameters, VM snapshot ID, and per-stream
   SHA-256 hashes. `harvest.sh` writes this; if it's missing,
   discard the run.
3. **pfctl re-enable**: if you disabled pfctl rules for the run,
   re-enable them (`sudo pfctl -e`).

## What goes wrong

- **Atomic egress to the public internet.** If a technique has a C2
  call-home and the safe-fire net failed to contain it, you may have
  beaconed to an attacker-controlled host. Mitigation: gate 1-4 above;
  also use Atomic Red Team's `--input-args destination=192.168.66.20`
  to pin C2 endpoints inside the sandbox.
- **Atomic propagation to the Mac host.** Worm-style techniques on
  Windows can try LAN scans. The pfctl rules + host-only network
  mode prevent any pkt from reaching en0.
- **Persistent compromise of the VM image.** Some techniques modify
  the bootloader or WMI subscribers. Snapshot revert after every run
  is the only reliable mitigation. Do not skip step 1 of post-run
  hygiene.
- **Detection telemetry contamination.** If you forget to restore the
  VM between two technique runs, the second run's EVTX will contain
  events from the first, and the model can pattern-match the
  combination as "two-technique chain" when the corpus design only
  expected one. Revert. Always.
