import json
import logging
import os
import sys
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

firehose_client = boto3.client("firehose")

STREAM_NAME = os.environ["STREAM_NAME"]

EVENT_NAME_EXCLUDED_LIST = [
    e.strip() for e in os.environ.get("EVENT_NAME_EXCLUDED_LIST", "").split(",") if e.strip()
]

EVENT_ROLE_ARN_EXCLUDED_LIST = [
    r.strip() for r in os.environ.get("EVENT_ROLE_ARN_EXCLUDED_LIST", "").split(",") if r.strip()
]

MAX_RECORD_BATCH_SIZE = 1_000_000
MAX_RECORD_BATCH_LENGTH = 500


def check_event_excluded(event):
    """
    Exclude events based on:
    - eventName
    - role ARN suffix match
    """
    if event.get("eventName") not in EVENT_NAME_EXCLUDED_LIST:
        return False

    roles = [
        event.get("userIdentity", {}).get("arn"),
        event.get("userIdentity", {})
            .get("sessionContext", {})
            .get("sessionIssuer", {})
            .get("arn"),
    ]

    if isinstance(event.get("resources"), list):
        for r in event["resources"]:
            if isinstance(r, dict) and "ARN" in r:
                roles.append(r["ARN"])

    for role in roles:
        if isinstance(role, str):
            for excluded in EVENT_ROLE_ARN_EXCLUDED_LIST:
                if role.endswith(excluded):
                    return True

    return False


def send_to_firehose(records):
    """
    Sends CloudTrail events to Firehose in batches
    """
    batch = []
    batch_size = 0

    for record in records:
        serialized = json.dumps(record)
        record_size = sys.getsizeof(serialized)

        if record_size > MAX_RECORD_BATCH_SIZE:
            logger.warning("Single CloudTrail event exceeds Firehose size limit")
            continue

        if (
            batch_size + record_size > MAX_RECORD_BATCH_SIZE
            or len(batch) >= MAX_RECORD_BATCH_LENGTH
        ):
            firehose_client.put_record_batch(
                DeliveryStreamName=STREAM_NAME,
                Records=[{"Data": json.dumps(batch)}],
            )
            batch = []
            batch_size = 0

        batch.append(record)
        batch_size += record_size

    if batch:
        firehose_client.put_record_batch(
            DeliveryStreamName=STREAM_NAME,
            Records=[{"Data": json.dumps(batch)}],
        )


def lambda_handler(event, context):
    logger.info("Received EventBridge event")
    logger.info("Event: %s", json.dumps(event))

    if event.get("detail-type") != "AWS API Call via CloudTrail":
        logger.warning("Ignoring non-CloudTrail event")
        return {"statusCode": 200, "body": "Ignored non-CloudTrail event"}

    cloudtrail_event = event.get("detail")
    if not isinstance(cloudtrail_event, dict):
        logger.warning("Malformed CloudTrail detail")
        return {"statusCode": 200, "body": "Malformed CloudTrail event"}

    if check_event_excluded(cloudtrail_event):
        logger.info(
            "Excluded event %s by %s",
            cloudtrail_event.get("eventName"),
            cloudtrail_event.get("eventSource"),
        )
        return {"statusCode": 200, "body": "Event excluded"}

    send_to_firehose([cloudtrail_event])

    logger.info(
        "Successfully forwarded event %s from %s",
        cloudtrail_event.get("eventName"),
        cloudtrail_event.get("eventSource"),
    )

    return {
        "statusCode": 200,
        "body": "CloudTrail event processed",
    }
