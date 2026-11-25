#!/usr/bin/env bash
# Make one risky change in a TEST account, wait for the alert, then undo it.
# Usage: scripts/simulate.sh ssh|s3   (needs AWS credentials and a deployed stack)
set -euo pipefail

REGION="${AWS_REGION:-eu-west-2}"
case "${1:-}" in
  ssh)
    VPC_ID=$(aws ec2 describe-vpcs --region "$REGION" --filters Name=isDefault,Values=true \
      --query 'Vpcs[0].VpcId' --output text)
    SG_ID=$(aws ec2 create-security-group --region "$REGION" --vpc-id "$VPC_ID" \
      --group-name "detector-test-$(date +%s)" --description "misconfig detector test" \
      --query GroupId --output text)
    echo "Created $SG_ID. Opening SSH to 0.0.0.0/0 ..."
    aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
      --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null
    echo "Wait about 1-5 minutes for the e-mail (CloudTrail delivery delay). Press Enter to clean up."
    read -r
    aws ec2 delete-security-group --region "$REGION" --group-id "$SG_ID"
    echo "Deleted $SG_ID."
    ;;
  s3)
    BUCKET="detector-test-$(date +%s)-$RANDOM"
    aws s3api create-bucket --region "$REGION" --bucket "$BUCKET" \
      --create-bucket-configuration LocationConstraint="$REGION" >/dev/null
    echo "Created $BUCKET. Removing Block Public Access ..."
    aws s3api delete-public-access-block --bucket "$BUCKET"
    echo "Wait about 1-5 minutes for the e-mail. Press Enter to clean up."
    read -r
    aws s3api delete-bucket --bucket "$BUCKET"
    echo "Deleted $BUCKET."
    ;;
  *)
    echo "usage: $0 ssh|s3" >&2
    exit 2
    ;;
esac
