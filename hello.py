import json
import logging
import os
import urllib.parse
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

US_COMPLIANT_ACCOUNTS = [
    acc.strip() for acc in os.environ["US_COMPLIANT_ACCOUNTS"].split(",")
]
US_COMPLIANT_QUEUE_URL = os.environ["US_COMPLIANT_QUEUE_URL"]
NON_US_COMPLIANT_QUEUE_URL = os.environ["NON_US_COMPLIANT_QUEUE_URL"]
REGION_NAME = os.environ["REGION_NAME"]


def get_account_id_from_key(key):
    """
    Extracts the first 12-digit account ID found in the S3 key path.
    Works for both:
    - AWSLogs/<account-id>/...
    - AWSLogs/<org-id>/<account-id>/...
    """
    try:
        for part in key.split("/"):
            if len(part) == 12 and part.isdigit():
                return part

        logger.warning(f"Could not find 12-digit account ID in key: {key}")
        return None

    except Exception as e:
        logger.warning(f"Error extracting account ID from key: {key}, error: {str(e)}")
        return None


def lambda_handler(event, context):

    logger.info("Received S3 event")
    logger.info(json.dumps(event))

    sqs = boto3.client("sqs", region_name=REGION_NAME)

    try:
        for record in event.get("Records", []):

            try:
                bucket = record["s3"]["bucket"]["name"]
                key = urllib.parse.unquote_plus(record["s3"]["object"]["key"])

                logger.info(f"Processing object: s3://{bucket}/{key}")

                account_id = get_account_id_from_key(key)

                if account_id:
                    logger.info(f"Extracted account ID: {account_id}")
                else:
                    logger.warning("Account ID not found, defaulting to NON_US_COMPLIANT")

                if account_id in US_COMPLIANT_ACCOUNTS:
                    queue_url = US_COMPLIANT_QUEUE_URL
                    queue_label = "US_COMPLIANT"
                else:
                    queue_url = NON_US_COMPLIANT_QUEUE_URL
                    queue_label = "NON_US_COMPLIANT"

                logger.info(f"Routing to queue: {queue_label}")
                idempotency_key = f"{bucket}/{key}"
                event_id = record.get("eventID")
                if event_id:
                    idempotency_key = f"{idempotency_key}:{event_id}"

                message_body = json.dumps({
                    "Records": [record],
                    "idempotencyKey": idempotency_key
                })

                logger.info(f"SQS Message Body: {message_body}")

                response = sqs.send_message(
                    QueueUrl=queue_url,
                    MessageBody=message_body
                )

                logger.info(
                    f"Message sent successfully. MessageId: {response['MessageId']}"
                )

            except Exception:
                logger.exception("Error processing individual record")
                # Continue processing remaining records
                continue

    except Exception as e:
        logger.exception("Fatal error processing event")
        raise e

    return {
        "statusCode": 200,
        "body": "Processing complete"
    }
