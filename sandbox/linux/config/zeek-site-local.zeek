# local.zeek for the sandbox Zeek deployment.
#
# Capture intent: per-flow conn.log + per-protocol logs (dns / http /
# ssl / files) matching the field set the IT baseline's network_zeek
# generator emits. Anything wider here forces the synthetic side to
# widen too before fixtures are comparable.

@load base/frameworks/notice

# Disable channels we won't ship into the harvested capture (keeps
# the per-run output small and focused).
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
@load policy/protocols/ssh/detect-bruteforcing

# Tap interface: in UTM host-only mode the sandbox VM sees all of
# sandbox-net via enp0s2. zeekctl reads this from node.cfg, not from
# this file, but pin the doc comment here so future readers know.

# Tighten log rotation so harvest can grab a clean slice without
# truncated lines.
redef Log::default_rotation_interval = 1 hr;

# Plant a marker comment in every produced log file: makes it easy to
# distinguish sandbox-derived captures from baseline-synthetic Zeek
# output in downstream debugging.
event zeek_init() {
    print fmt("blue-bench sandbox zeek site loaded at %s", current_time());
}
