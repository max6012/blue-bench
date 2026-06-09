#!/usr/bin/env bash
# Provision the isolated AWS network scaffold for the t-sandbox
# capture substrate. Idempotent-ish: writes every resource ID to
# aws-resources.env as it goes so a partial failure is recoverable
# (and aws-teardown.sh can clean up from that file).
#
# Cost: $0 -- VPC, subnet, IGW, route table, security group, and
# key pair carry no hourly charge. Only instances bill.
#
# Usage: ./aws-provision-net.sh

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ENVFILE="$HERE/aws-resources.env"
REGION="${AWS_REGION:-us-east-1}"
PROJECT_TAG="Project=blue-bench"
KEY_NAME="bb-sandbox"
PUBKEY="$HOME/.ssh/bb-sandbox-ed25519.pub"

VPC_CIDR="10.20.0.0/16"
SUBNET_CIDR="10.20.1.0/24"

tag_spec() { echo "ResourceType=$1,Tags=[{Key=Project,Value=blue-bench},{Key=Name,Value=$2}]"; }
record() { echo "$1=$2" >> "$ENVFILE"; echo "  $1=$2"; }

echo "region: $REGION"
MYIP="$(curl -s --max-time 10 https://checkip.amazonaws.com | tr -d '\n')"
echo "operator IP (SSH ingress): $MYIP/32"

# Fresh env file (back up any prior).
[[ -f $ENVFILE ]] && mv "$ENVFILE" "$ENVFILE.bak.$(date +%s)"
{
  echo "# bb-sandbox AWS resources -- generated $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "AWS_REGION=$REGION"
  echo "SSH_INGRESS_CIDR=$MYIP/32"
} > "$ENVFILE"

echo "=== VPC ==="
VPC_ID=$(aws ec2 create-vpc --region "$REGION" --cidr-block "$VPC_CIDR" \
  --tag-specifications "$(tag_spec vpc bb-sandbox-vpc)" \
  --query 'Vpc.VpcId' --output text)
record VPC_ID "$VPC_ID"
aws ec2 modify-vpc-attribute --region "$REGION" --vpc-id "$VPC_ID" --enable-dns-hostnames
aws ec2 modify-vpc-attribute --region "$REGION" --vpc-id "$VPC_ID" --enable-dns-support

echo "=== Internet gateway ==="
IGW_ID=$(aws ec2 create-internet-gateway --region "$REGION" \
  --tag-specifications "$(tag_spec internet-gateway bb-sandbox-igw)" \
  --query 'InternetGateway.InternetGatewayId' --output text)
record IGW_ID "$IGW_ID"
aws ec2 attach-internet-gateway --region "$REGION" --internet-gateway-id "$IGW_ID" --vpc-id "$VPC_ID"

echo "=== Subnet ==="
SUBNET_ID=$(aws ec2 create-subnet --region "$REGION" --vpc-id "$VPC_ID" \
  --cidr-block "$SUBNET_CIDR" \
  --tag-specifications "$(tag_spec subnet bb-sandbox-subnet)" \
  --query 'Subnet.SubnetId' --output text)
record SUBNET_ID "$SUBNET_ID"
aws ec2 modify-subnet-attribute --region "$REGION" --subnet-id "$SUBNET_ID" --map-public-ip-on-launch

echo "=== Route table ==="
RT_ID=$(aws ec2 create-route-table --region "$REGION" --vpc-id "$VPC_ID" \
  --tag-specifications "$(tag_spec route-table bb-sandbox-rt)" \
  --query 'RouteTable.RouteTableId' --output text)
record RT_ID "$RT_ID"
aws ec2 create-route --region "$REGION" --route-table-id "$RT_ID" \
  --destination-cidr-block 0.0.0.0/0 --gateway-id "$IGW_ID" >/dev/null
aws ec2 associate-route-table --region "$REGION" --route-table-id "$RT_ID" --subnet-id "$SUBNET_ID" >/dev/null

echo "=== Security group ==="
SG_ID=$(aws ec2 create-security-group --region "$REGION" \
  --group-name bb-sandbox-sg --description "bb-sandbox capture substrate" \
  --vpc-id "$VPC_ID" \
  --tag-specifications "$(tag_spec security-group bb-sandbox-sg)" \
  --query 'GroupId' --output text)
record SG_ID "$SG_ID"
# SSH from operator IP only.
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
  --protocol tcp --port 22 --cidr "$MYIP/32" >/dev/null
# Intra-SG: allow all so the Zeek mirror target + Windows host can talk.
aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
  --protocol -1 --source-group "$SG_ID" >/dev/null

echo "=== Key pair ==="
if aws ec2 describe-key-pairs --region "$REGION" --key-names "$KEY_NAME" >/dev/null 2>&1; then
  echo "  key pair $KEY_NAME already exists -- reusing"
else
  aws ec2 import-key-pair --region "$REGION" --key-name "$KEY_NAME" \
    --public-key-material "fileb://$PUBKEY" >/dev/null
fi
record KEY_NAME "$KEY_NAME"

echo
echo "OK: network scaffold provisioned. Resource IDs -> $ENVFILE"
cat "$ENVFILE"
