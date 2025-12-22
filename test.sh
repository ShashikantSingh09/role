#!/bin/bash
set -e

# ==========================
# CONFIGURATION
# ==========================
S3_BUCKET_ARN="arn:aws:s3:::laitkor-guardduty-test-key"
KMS_KEY_ARN="arn:aws:kms:us-west-2:891572012759:key/c8547737-c0da-41de-9b13-4e1995826f49"

# ==========================
# GET ALL AWS REGIONS
# ==========================
REGIONS=$(aws ec2 describe-regions \
  --query "Regions[].RegionName" \
  --output text)

# ==========================
# LOOP THROUGH REGIONS
# ==========================
for REGION in $REGIONS; do
  echo "----------------------------------------"
  echo "Processing region: $REGION"

  # Get existing detector (if any)
  DETECTOR_ID=$(aws guardduty list-detectors \
    --region "$REGION" \
    --query "DetectorIds[0]" \
    --output text)

  # Create detector if it doesn't exist
  if [[ "$DETECTOR_ID" == "None" || -z "$DETECTOR_ID" ]]; then
    echo "No detector found. Creating GuardDuty detector..."
    DETECTOR_ID=$(aws guardduty create-detector \
      --enable \
      --region "$REGION" \
      --query "DetectorId" \
      --output text)
    echo "Created detector: $DETECTOR_ID"
  else
    echo "Found detector: $DETECTOR_ID"
  fi

  # Check if S3 publishing destination already exists
  DESTINATION_ID=$(aws guardduty list-publishing-destinations \
    --region "$REGION" \
    --detector-id "$DETECTOR_ID" \
    --query "DestinationIds[0]" \
    --output text)

  if [[ "$DESTINATION_ID" == "None" || -z "$DESTINATION_ID" ]]; then
    echo "Creating S3 publishing destination..."
    aws guardduty create-publishing-destination \
      --region "$REGION" \
      --detector-id "$DETECTOR_ID" \
      --destination-type S3 \
      --destination-properties \
        "DestinationArn=$S3_BUCKET_ARN,KmsKeyArn=$KMS_KEY_ARN"

    echo "S3 export enabled in $REGION"
  else
    echo "S3 export already configured in $REGION (Destination ID: $DESTINATION_ID)"
  fi

done

echo "----------------------------------------"
echo "GuardDuty S3 export configuration completed for all regions."
