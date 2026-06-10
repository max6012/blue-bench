#!/usr/bin/env bash
# Launch the Windows Server 2022 capture instance into the
# bb-sandbox VPC and wait for SSH. EC2 user-data (PowerShell, run by
# EC2Launch on first boot) enables OpenSSH, sets PowerShell as the
# default shell, drops the bb-sandbox admin key, and disables
# Defender real-time monitoring (so atomics aren't altered/blocked).
#
# Native x86 on Nitro -- the Add-WindowsCapability that took 5h under
# TCG runs in the normal ~1-2 min here.
#
# Usage: ./aws-launch-win.sh

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ENVFILE="$HERE/aws-resources.env"
[[ -f $ENVFILE ]] || { echo "ABORT: $ENVFILE missing -- run aws-provision-net.sh first" >&2; exit 1; }
# shellcheck disable=SC1090
source "$ENVFILE"

REGION="${AWS_REGION:-us-east-1}"
WIN_AMI="${WIN_AMI:-ami-0909cee4864578472}"   # Windows_Server-2022-English-Full-Base-2026.05.13
# m7i-flex.large (2 vCPU, 8 GB, x86 Nitro): this new free-tier
# account hard-blocks non-free-tier-eligible types, and t3.large is
# rejected. m7i-flex.large IS free-tier-eligible, x86, and has the
# 8 GB Windows wants. (Still bills against the $200 credits -- the
# gate is which types may launch, not cost.)
INSTANCE_TYPE="${WIN_INSTANCE_TYPE:-m7i-flex.large}"
PUBKEY="$(cat "$HOME/.ssh/bb-sandbox-ed25519.pub")"
SSH_KEY="$HOME/.ssh/bb-sandbox-ed25519"

# ---- user-data (EC2 Windows runs <powershell> on first boot) ----
# Quoted heredoc ('PSUD') so bash does ZERO interpolation -- every
# PowerShell $var and the (absent) backticks pass through verbatim.
# The pubkey is injected afterward via a __PUBKEY__ placeholder.
# Every statement is ONE line: no line-continuations (an earlier
# version used backticks that the bash heredoc mangled, aborting the
# script before the authorized-key drop). sshd is started LAST, so
# the port never opens before the key is in place.
UD="$(mktemp)"
trap 'rm -f "$UD"' EXIT
cat > "$UD" <<'PSUD'
<powershell>
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Set-Service -Name sshd -StartupType Automatic
New-Item -Path HKLM:\SOFTWARE\OpenSSH -Force | Out-Null
New-ItemProperty -Path HKLM:\SOFTWARE\OpenSSH -Name DefaultShell -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -PropertyType String -Force | Out-Null
New-Item -ItemType Directory -Path 'C:\ProgramData\ssh' -Force | Out-Null
Set-Content -Path 'C:\ProgramData\ssh\administrators_authorized_keys' -Value '__PUBKEY__' -Encoding ascii
icacls 'C:\ProgramData\ssh\administrators_authorized_keys' /inheritance:r | Out-Null
icacls 'C:\ProgramData\ssh\administrators_authorized_keys' /grant 'SYSTEM:F' | Out-Null
icacls 'C:\ProgramData\ssh\administrators_authorized_keys' /grant 'BUILTIN\Administrators:F' | Out-Null
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH SSH Server' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -ErrorAction SilentlyContinue | Out-Null
Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -ErrorAction SilentlyContinue
Start-Service sshd
</powershell>
PSUD
# Inject the real pubkey (| delimiter avoids clashing with / in keys).
sed -i '' "s|__PUBKEY__|$PUBKEY|" "$UD"

echo "Launching $INSTANCE_TYPE Windows ($WIN_AMI) into $SUBNET_ID ..."
# NOTE: no --key-name. EC2 Windows AMIs only accept RSA key pairs
# (used to encrypt the Administrator password), and we don't need
# that path -- SSH auth comes from the ed25519 administrators_
# authorized_keys the user-data drops. Omitting the key pair
# entirely is cleaner than importing a throwaway RSA key.
IID=$(aws ec2 run-instances --region "$REGION" \
  --image-id "$WIN_AMI" \
  --instance-type "$INSTANCE_TYPE" \
  --subnet-id "$SUBNET_ID" \
  --security-group-ids "$SG_ID" \
  --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=50,VolumeType=gp3}' \
  --user-data "file://$UD" \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Project,Value=blue-bench},{Key=Name,Value=bb-sandbox-win}]' \
  --query 'Instances[0].InstanceId' --output text)
echo "  instance: $IID"

# Record (strip any prior WIN_ lines, append fresh)
grep -v '^WIN_' "$ENVFILE" > "$ENVFILE.tmp" && mv "$ENVFILE.tmp" "$ENVFILE"
echo "WIN_INSTANCE_ID=$IID" >> "$ENVFILE"

echo "Waiting for instance running..."
aws ec2 wait instance-running --region "$REGION" --instance-ids "$IID"
PUBIP=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$IID" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
ENI=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$IID" \
  --query 'Reservations[0].Instances[0].NetworkInterfaces[0].NetworkInterfaceId' --output text)
echo "WIN_PUBLIC_IP=$PUBIP" >> "$ENVFILE"
echo "WIN_ENI=$ENI" >> "$ENVFILE"
echo "  public IP: $PUBIP   ENI: $ENI"

echo "Polling SSH (user-data + OpenSSH install takes a few min on first boot)..."
deadline=$(( $(date +%s) + 900 ))
ok=0
while (( $(date +%s) < deadline )); do
  if ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
       -o LogLevel=QUIET -o ConnectTimeout=8 -o BatchMode=yes \
       "sandbox@$PUBIP" "exit 0" 2>/dev/null; then ok=1; break; fi
  # EC2 Windows default admin user for key auth is 'Administrator';
  # try it too in case the local 'sandbox' user isn't present.
  if ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
       -o LogLevel=QUIET -o ConnectTimeout=8 -o BatchMode=yes \
       "Administrator@$PUBIP" "exit 0" 2>/dev/null; then ok=2; break; fi
  sleep 20
done

if [[ $ok -eq 0 ]]; then
  echo "ABORT: SSH never came up in 15 min. Instance $IID left running for diagnosis." >&2
  echo "  Check console: aws ec2 get-console-output --region $REGION --instance-id $IID --latest" >&2
  exit 1
fi
WINUSER=$([[ $ok -eq 2 ]] && echo Administrator || echo sandbox)
echo "WIN_SSH_USER=$WINUSER" >> "$ENVFILE"
echo "OK: SSH up as $WINUSER@$PUBIP"
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o LogLevel=QUIET -o BatchMode=yes "$WINUSER@$PUBIP" \
    "hostname; (Get-Service sshd).Status; [Environment]::OSVersion.VersionString" 2>&1 | head -5
echo
echo "Stop when idle:  aws ec2 stop-instances --region $REGION --instance-ids $IID"
