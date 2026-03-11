import logging
import os
import boto3
import json

logger = logging.getLogger()
logger.setLevel(logging.INFO)

US_COMPLIANT_ACCOUNTS = os.environ["US_COMPLIANT_ACCOUNTS"].split(",")
US_COMPLIANT_QUEUE_URL = os.environ["US_COMPLIANT_QUEUE_URL"]
NON_US_COMPLIANT_QUEUE_URL = os.environ["NON_US_COMPLIANT_QUEUE_URL"]
REGION_NAME = os.environ["REGION_NAME"]


def check_compliant_account(key):
    return any(account.strip() in key for account in US_COMPLIANT_ACCOUNTS)


def lambda_handler(event, context):
    logger.info("Starting CloudTrail forwarding (S3 path only)")

    try:
        if not event.get("Records"):
            return {"statusCode": 400, "body": "Invalid event format"}

        sqs = boto3.client("sqs", region_name=REGION_NAME)

        bucket = event["Records"][0]["s3"]["bucket"]["name"]
        key = event["Records"][0]["s3"]["object"]["key"]

        logger.info(f"Processing S3 object path: s3://{bucket}/{key}")

        # Message containing only the S3 path
        message_body = json.dumps({
            "bucket": bucket,
            "key": key,
            "s3_uri": f"s3://{bucket}/{key}"
        })

        queue_url = (
            US_COMPLIANT_QUEUE_URL
            if check_compliant_account(key)
            else NON_US_COMPLIANT_QUEUE_URL
        )

        sqs.send_message(
            QueueUrl=queue_url,
            MessageBody=message_body
        )

        logger.info("S3 path sent to SQS successfully")

    except Exception as e:
        logger.exception("Error processing file")

    return {
        "statusCode": 200,
        "body": "Processing complete"
    }
