import gzip
import json
import logging
import os
import sys
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

firehose_client = boto3.client("firehose")

STREAM_NAME = os.environ["STREAM_NAME"]
REGION_NAME = os.environ["REGION_NAME"]

EVENT_NAME_EXCLUDED_LIST = [
    e.strip() for e in os.environ["EVENT_NAME_EXCLUDED_LIST"].split(",") if e.strip()
]

EVENT_ROLE_ARN_EXCLUDED_LIST = [
    r.strip() for r in os.environ["EVENT_ROLE_ARN_EXCLUDED_LIST"].split(",") if r.strip()
]

MAX_RECORD_BATCH_SIZE = 1_000_000  # 1 MB
MAX_RECORD_BATCH_LENGTH = 500

def parse_gzip_log_file(s3_client, bucket, key):
    response = s3_client.get_object(Bucket=bucket, Key=key)
    with gzip.GzipFile(fileobj=response["Body"]) as f:
        return json.loads(f.read().decode("utf-8"))


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


def filter_cloudtrail_events(data):
    """
    Filters CloudTrail records and batches them for Firehose
    """
    if not isinstance(data, dict) or "Records" not in data:
        return []

    batches = []
    current_batch = []

    for record in data["Records"]:
        if sys.getsizeof(record) > MAX_RECORD_BATCH_SIZE:
            logger.warning("Single CloudTrail record exceeds Firehose size limit")
            continue

        if check_event_excluded(record):
            continue

        serialized = json.dumps(current_batch + [record])

        if sys.getsizeof(serialized) > MAX_RECORD_BATCH_SIZE:
            batches.append(json.dumps(current_batch))
            current_batch = [record]
        else:
            current_batch.append(record)

        if len(current_batch) >= MAX_RECORD_BATCH_LENGTH:
            batches.append(json.dumps(current_batch))
            current_batch = []

    if current_batch:
        batches.append(json.dumps(current_batch))

    return batches


def send_to_firehose(batches):
    for batch in batches:
        firehose_client.put_record_batch(
            DeliveryStreamName=STREAM_NAME,
            Records=[{"Data": batch}],
        )

def lambda_handler(event, context):
    logger.info("Starting CloudTrail log processing")
    logger.info("Incoming event: %s", json.dumps(event))

    records = event.get("Records")
    if not isinstance(records, list) or not records:
        logger.warning("Non-S3 or malformed event received. Ignoring.")
        return {
            "statusCode": 200,
            "body": "Ignored non-S3 event",
        }

    record = records[0]

    if record.get("eventSource") != "aws:s3":
        logger.warning("Event source is not S3. Ignoring.")
        return {
            "statusCode": 200,
            "body": "Ignored non-S3 source",
        }

    try:
        bucket = record["s3"]["bucket"]["name"]
        key = record["s3"]["object"]["key"]

        logger.info("Processing object s3://%s/%s", bucket, key)

        s3_client = boto3.client("s3", region_name=REGION_NAME)

        content = parse_gzip_log_file(s3_client, bucket, key)
        batches = filter_cloudtrail_events(content)

        if batches:
            send_to_firehose(batches)
            logger.info("Successfully sent %d batch(es) to Firehose", len(batches))
        else:
            logger.info("No CloudTrail records after filtering")

    except Exception as e:
        logger.exception("Failed processing CloudTrail logs")
        raise e

    return {
        "statusCode": 200,
        "body": "Processing complete",
    }
