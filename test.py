import json
import logging
import os
import urllib.parse
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

US_COMPLIANT_ACCOUNTS = [
    str(acc).strip().replace('"', '').replace("'", "")
    for acc in os.environ["US_COMPLIANT_ACCOUNTS"].split(",")
]

US_COMPLIANT_QUEUE_URL = os.environ["US_COMPLIANT_QUEUE_URL"]
NON_US_COMPLIANT_QUEUE_URL = os.environ["NON_US_COMPLIANT_QUEUE_URL"]
REGION_NAME = os.environ["REGION_NAME"]


def normalize(value):
    return str(value).strip() if value else None


def get_account_id_from_key(key):
    parts = key.split("/")

    if "AWSLogs" not in parts:
        logger.warning(f"AWSLogs not found in key: {key}")
        return None

    try:
        idx = parts.index("AWSLogs")

        # Detect org trail
        if len(parts) > idx + 2 and parts[idx + 1].startswith("o-"):
            return normalize(parts[idx + 2])
        elif len(parts) > idx + 1:
            return normalize(parts[idx + 1])
        else:
            return None

    except Exception as e:
        logger.error(f"Error extracting account ID: {e}")
        return None


def lambda_handler(event, context):

    logger.info("Lambda execution started")
    logger.info(json.dumps(event))

    try:
        sqs = boto3.client("sqs", region_name=REGION_NAME)

        normalized_accounts = [normalize(acc) for acc in US_COMPLIANT_ACCOUNTS]

        logger.info(f"Compliant accounts: {normalized_accounts}")

        for record in event.get("Records", []):

            try:
                bucket = record["s3"]["bucket"]["name"]
                key = urllib.parse.unquote_plus(record["s3"]["object"]["key"])

                logger.info(f"S3 Object: s3://{bucket}/{key}")
                logger.info(f"S3 Key Parts: {key.split('/')}")

                account_id = get_account_id_from_key(key)

                logger.info(f"Extracted account_id: {repr(account_id)}")

                is_compliant = account_id in normalized_accounts if account_id else False

                logger.info(f"Final match result: {is_compliant}")

                if is_compliant:
                    queue_url = US_COMPLIANT_QUEUE_URL
                    queue_label = "US_COMPLIANT"
                else:
                    queue_url = NON_US_COMPLIANT_QUEUE_URL
                    queue_label = "NON_US_COMPLIANT"

                logger.info(f"Routing to queue: {queue_label}")

                message_body = json.dumps({
                    "Records": [record]
                })

                sqs.send_message(
                    QueueUrl=queue_url,
                    MessageBody=message_body
                )

                logger.info("Message sent successfully")

            except Exception as e:
                logger.exception(f"Error processing record: {e}")
                continue

    except Exception as e:
        logger.exception("Fatal error in lambda")
        return {"statusCode": 500, "body": str(e)}

    return {"statusCode": 200, "body": "Processing complete"}
