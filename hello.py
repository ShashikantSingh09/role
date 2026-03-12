import logging
import os
import urllib.parse
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

US_COMPLIANT_ACCOUNTS = os.environ["US_COMPLIANT_ACCOUNTS"].split(",")
US_COMPLIANT_QUEUE_URL = os.environ["US_COMPLIANT_QUEUE_URL"]
NON_US_COMPLIANT_QUEUE_URL = os.environ["NON_US_COMPLIANT_QUEUE_URL"]
REGION_NAME = os.environ["REGION_NAME"]


def check_compliant_account(key):
    """
    Extract account ID from CloudTrail path:
    AWSLogs/<ACCOUNT_ID>/CloudTrail/...
    """
    try:
        account_id = key.split("/")[1]
        return account_id in US_COMPLIANT_ACCOUNTS
    except Exception:
        logger.warning("Could not determine account from key")
        return False


def lambda_handler(event, context):

    logger.info("Starting CloudTrail forwarding to Google SecOps")

    try:
        if "Records" not in event:
            logger.error("Invalid event format")
            return {"statusCode": 400, "body": "Invalid event format"}

        sqs = boto3.client("sqs", region_name=REGION_NAME)

        for record in event["Records"]:

            bucket = record["s3"]["bucket"]["name"]
            key = urllib.parse.unquote_plus(record["s3"]["object"]["key"])

            s3_uri = f"s3://{bucket}/{key}"

            logger.info(f"Processing object: {s3_uri}")

            queue_url = (
                US_COMPLIANT_QUEUE_URL
                if check_compliant_account(key)
                else NON_US_COMPLIANT_QUEUE_URL
            )

            queue_label = (
                "US_COMPLIANT"
                if queue_url == US_COMPLIANT_QUEUE_URL
                else "NON_US_COMPLIANT"
            )

            logger.info(f"Selected queue: {queue_label}")

            sqs.send_message(
                QueueUrl=queue_url,
                MessageBody=s3_uri
            )

            logger.info(f"Forwarded {s3_uri} to {queue_label} queue")

    except Exception as e:
        logger.exception("Error processing event")
        return {"statusCode": 500, "body": str(e)}

    return {"statusCode": 200, "body": "Processing complete"}
