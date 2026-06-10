#!/usr/bin/env bash
# Start the stopped bb-sandbox instances and refresh runtime state.
# stop/start gives new public IPs (the ENIs + private IPs persist,
# so the mirror session survives; vxlan0 is re-created by its
# systemd unit on the Zeek boot). Refreshes WIN_/ZEEK_PUBLIC_IP in
# aws-resources.env and re-points the SG SSH ingress at the
# operator's current public IP. Verifies SSH to both.
#
# Usage: ./aws-start.sh

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ENVFILE="$HERE/aws-resources.env"
# shellcheck disable=SC1090
source "$ENVFILE"
REGION="${AWS_REGION:-us-east-1}"
SSH_KEY="$HOME/.ssh/bb-sandbox-ed25519"

echo "=== starting instances ==="
aws ec2 start-instances --region "$REGION" \
  --instance-ids "$WIN_INSTANCE_ID" "$ZEEK_INSTANCE_ID" \
  --query 'StartingInstances[].{ID:InstanceId,State:CurrentState.Name}' --output text
aws ec2 wait instance-running --region "$REGION" \
  --instance-ids "$WIN_INSTANCE_ID" "$ZEEK_INSTANCE_ID"

refresh_ip() {  # $1=instance-id  $2=env-prefix
  local ip; ip=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$1" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
  grep -v "^${2}_PUBLIC_IP=" "$ENVFILE" > "$ENVFILE.tmp" && mv "$ENVFILE.tmp" "$ENVFILE"
  echo "${2}_PUBLIC_IP=$ip" >> "$ENVFILE"
  echo "$ip"
}
WIN_IP=$(refresh_ip "$WIN_INSTANCE_ID" WIN)
ZEEK_IP=$(refresh_ip "$ZEEK_INSTANCE_ID" ZEEK)
echo "  Win:  $WIN_IP"
echo "  Zeek: $ZEEK_IP"

echo "=== refresh SG SSH ingress to current operator IP ==="
MYIP="$(curl -s --max-time 10 https://checkip.amazonaws.com | tr -d '\n')"
OLD_CIDR="${SSH_INGRESS_CIDR:-}"
if [[ "$MYIP/32" != "$OLD_CIDR" ]]; then
  [[ -n $OLD_CIDR ]] && aws ec2 revoke-security-group-ingress --region "$REGION" \
    --group-id "$SG_ID" --protocol tcp --port 22 --cidr "$OLD_CIDR" 2>/dev/null || true
  aws ec2 authorize-security-group-ingress --region "$REGION" \
    --group-id "$SG_ID" --protocol tcp --port 22 --cidr "$MYIP/32" 2>/dev/null || true
  grep -v '^SSH_INGRESS_CIDR=' "$ENVFILE" > "$ENVFILE.tmp" && mv "$ENVFILE.tmp" "$ENVFILE"
  echo "SSH_INGRESS_CIDR=$MYIP/32" >> "$ENVFILE"
  echo "  ingress now $MYIP/32 (was ${OLD_CIDR:-none})"
else
  echo "  ingress unchanged ($MYIP/32)"
fi

echo "=== verify SSH (sshd/sysmon may take ~1 min after boot) ==="
SSHO=(-i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=QUIET -o ConnectTimeout=8 -o BatchMode=yes)
for spec in "$WIN_SSH_USER@$WIN_IP:Windows" "ubuntu@$ZEEK_IP:Zeek"; do
  ua="${spec%:*}"; label="${spec##*:}"; ok=0
  for _ in $(seq 1 30); do
    if ssh "${SSHO[@]}" "$ua" "exit 0" 2>/dev/null; then ok=1; break; fi
    sleep 10
  done
  [[ $ok -eq 1 ]] && echo "  $label SSH OK ($ua)" || { echo "  $label SSH FAILED ($ua)" >&2; exit 1; }
done

echo "=== re-assert vxlan0 on Zeek (systemd unit should have run) ==="
ssh "${SSHO[@]}" "ubuntu@$ZEEK_IP" 'systemctl is-active bb-vxlan.service; ip -br link show vxlan0 2>/dev/null || (sudo systemctl restart bb-vxlan.service; ip -br link show vxlan0)' 2>&1 | tail -2

echo
echo "OK: substrate up. Win=$WIN_IP Zeek=$ZEEK_IP"
