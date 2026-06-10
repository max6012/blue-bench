#!/usr/bin/env bash
# Wire VPC Traffic Mirroring: mirror the Windows capture host's ENI
# to the Zeek sensor's ENI. AWS encapsulates mirrored packets in
# VXLAN (UDP/4789) to the target; the Zeek host's vxlan0 (from its
# user-data) decapsulates them for Zeek/Suricata.
#
# Idempotent-ish: records mirror resource IDs to aws-resources.env.
# Usage: ./aws-mirror.sh

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ENVFILE="$HERE/aws-resources.env"
# shellcheck disable=SC1090
source "$ENVFILE"
REGION="${AWS_REGION:-us-east-1}"

: "${WIN_ENI:?run aws-launch-win.sh first}"
: "${ZEEK_ENI:?run aws-launch-zeek.sh first}"

record() { grep -v "^$1=" "$ENVFILE" > "$ENVFILE.tmp" && mv "$ENVFILE.tmp" "$ENVFILE"; echo "$1=$2" >> "$ENVFILE"; echo "  $1=$2"; }

echo "=== mirror target (Zeek ENI $ZEEK_ENI) ==="
TGT=$(aws ec2 create-traffic-mirror-target --region "$REGION" \
  --network-interface-id "$ZEEK_ENI" \
  --description "bb-sandbox zeek sensor" \
  --tag-specifications 'ResourceType=traffic-mirror-target,Tags=[{Key=Project,Value=blue-bench}]' \
  --query 'TrafficMirrorTarget.TrafficMirrorTargetId' --output text)
record MIRROR_TARGET_ID "$TGT"

echo "=== mirror filter + accept-all rules ==="
FIL=$(aws ec2 create-traffic-mirror-filter --region "$REGION" \
  --description "bb-sandbox accept-all" \
  --tag-specifications 'ResourceType=traffic-mirror-filter,Tags=[{Key=Project,Value=blue-bench}]' \
  --query 'TrafficMirrorFilter.TrafficMirrorFilterId' --output text)
record MIRROR_FILTER_ID "$FIL"
for dir in ingress egress; do
  aws ec2 create-traffic-mirror-filter-rule --region "$REGION" \
    --traffic-mirror-filter-id "$FIL" \
    --traffic-direction "$dir" --rule-number 100 --rule-action accept \
    --source-cidr-block 0.0.0.0/0 --destination-cidr-block 0.0.0.0/0 >/dev/null
done

echo "=== mirror session (source = Windows ENI $WIN_ENI) ==="
# --virtual-network-id 1 is PINNED (not auto-assigned): the Zeek
# host's vxlan0 must use the same VNI to decapsulate, so a fixed
# value keeps the sensor setup reproducible. (Auto-assign hands out
# a random VNI -- e.g. 6954049 -- which silently won't match a
# vxlan0 created with a different id.)
SES=$(aws ec2 create-traffic-mirror-session --region "$REGION" \
  --network-interface-id "$WIN_ENI" \
  --traffic-mirror-target-id "$TGT" \
  --traffic-mirror-filter-id "$FIL" \
  --session-number 1 \
  --virtual-network-id 1 \
  --description "bb-sandbox win->zeek" \
  --tag-specifications 'ResourceType=traffic-mirror-session,Tags=[{Key=Project,Value=blue-bench}]' \
  --query 'TrafficMirrorSession.TrafficMirrorSessionId' --output text)
record MIRROR_SESSION_ID "$SES"

echo
echo "OK: mirror live. Windows ENI traffic -> VXLAN -> Zeek ENI."
