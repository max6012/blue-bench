#!/usr/bin/env bash
# Launch the Linux Zeek/Suricata sensor into the bb-sandbox VPC.
# Ubuntu 24.04 (Zeek has clean apt packages via the OpenSUSE build
# service; Amazon Linux would mean building from source). ed25519
# key pair works fine on Linux AMIs. user-data installs Zeek +
# Suricata + a vxlan-decap helper (AWS Traffic Mirroring delivers
# VXLAN/4789 to the target ENI; we terminate it on a vxlan0 iface
# that Zeek/Suricata then sniff).
#
# Usage: ./aws-launch-zeek.sh

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ENVFILE="$HERE/aws-resources.env"
[[ -f $ENVFILE ]] || { echo "ABORT: $ENVFILE missing -- run aws-provision-net.sh first" >&2; exit 1; }
# shellcheck disable=SC1090
source "$ENVFILE"

REGION="${AWS_REGION:-us-east-1}"
ZEEK_AMI="${ZEEK_AMI:-ami-0021ac0c2e69d9c55}"   # Ubuntu 24.04 amd64 2026-06-04
INSTANCE_TYPE="${ZEEK_INSTANCE_TYPE:-c7i-flex.large}"   # free-tier-eligible x86, 4 GB
SSH_KEY="$HOME/.ssh/bb-sandbox-ed25519"

UD="$(mktemp)"
trap 'rm -f "$UD"' EXIT
cat > "$UD" <<'CLOUDINIT'
#!/bin/bash
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive
# Zeek apt repo (OpenSUSE build service)
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' > /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key | gpg --dearmor -o /etc/apt/trusted.gpg.d/security_zeek.gpg
apt-get update -y
apt-get install -y zeek suricata jq tcpdump
# VXLAN decap interface for AWS Traffic Mirroring (UDP 4789).
# VNI 1 MUST match the mirror session's --virtual-network-id (see
# aws-mirror.sh). The primary iface is detected from the default
# route -- on Nitro Ubuntu 24.04 it is enp39s0, NOT ens5/eth0, so
# a hardcoded name fails. Installed as a systemd oneshot so vxlan0
# survives reboot.
cat > /usr/local/sbin/bb-vxlan-up.sh <<'EOS'
#!/bin/bash
IF=$(ip -o -4 route show to default | awk '{print $5}' | head -1)
ip link del vxlan0 2>/dev/null || true
ip link add vxlan0 type vxlan id 1 dev "$IF" dstport 4789
ip link set vxlan0 up
EOS
chmod +x /usr/local/sbin/bb-vxlan-up.sh
cat > /etc/systemd/system/bb-vxlan.service <<'EOS'
[Unit]
Description=bb-sandbox VXLAN decap for AWS Traffic Mirroring
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/bb-vxlan-up.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOS
systemctl daemon-reload
systemctl enable --now bb-vxlan.service || true
touch /var/log/bb-zeek-provisioned
CLOUDINIT

echo "Launching $INSTANCE_TYPE Ubuntu Zeek sensor ($ZEEK_AMI) into $SUBNET_ID ..."
IID=$(aws ec2 run-instances --region "$REGION" \
  --image-id "$ZEEK_AMI" \
  --instance-type "$INSTANCE_TYPE" \
  --key-name "$KEY_NAME" \
  --subnet-id "$SUBNET_ID" \
  --security-group-ids "$SG_ID" \
  --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=30,VolumeType=gp3}' \
  --user-data "file://$UD" \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Project,Value=blue-bench},{Key=Name,Value=bb-sandbox-zeek}]' \
  --query 'Instances[0].InstanceId' --output text)
echo "  instance: $IID"

grep -v '^ZEEK_' "$ENVFILE" > "$ENVFILE.tmp" && mv "$ENVFILE.tmp" "$ENVFILE"
echo "ZEEK_INSTANCE_ID=$IID" >> "$ENVFILE"

aws ec2 wait instance-running --region "$REGION" --instance-ids "$IID"
PUBIP=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$IID" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
ENI=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$IID" \
  --query 'Reservations[0].Instances[0].NetworkInterfaces[0].NetworkInterfaceId' --output text)
echo "ZEEK_PUBLIC_IP=$PUBIP" >> "$ENVFILE"
echo "ZEEK_ENI=$ENI" >> "$ENVFILE"
echo "  public IP: $PUBIP   ENI: $ENI"

echo "Polling SSH..."
deadline=$(( $(date +%s) + 600 ))
ok=0
while (( $(date +%s) < deadline )); do
  if ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
       -o LogLevel=QUIET -o ConnectTimeout=8 -o BatchMode=yes \
       "ubuntu@$PUBIP" "exit 0" 2>/dev/null; then ok=1; break; fi
  sleep 15
done
[[ $ok -eq 1 ]] || { echo "ABORT: SSH never came up. Instance $IID left for diagnosis." >&2; exit 1; }
echo "ZEEK_SSH_USER=ubuntu" >> "$ENVFILE"
echo "OK: SSH up as ubuntu@$PUBIP"
echo
echo "Stop when idle:  aws ec2 stop-instances --region $REGION --instance-ids $IID"
