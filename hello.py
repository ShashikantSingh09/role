import json
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
    return any(account.strip() in key for account in US_COMPLIANT_ACCOUNTS)


def lambda_handler(event, context):
    logger.info("Starting CloudTrail S3 notification forwarding to Google SecOps")

    try:
        if not event.get("Records"):
            return {"statusCode": 400, "body": "Invalid event format"}

        sqs = boto3.client("sqs")

        for record in event["Records"]:
            bucket = record["s3"]["bucket"]["name"]
            key = urllib.parse.unquote_plus(
                record["s3"]["object"]["key"]
            )

            logger.info(f"Processing object: s3://{bucket}/{key}")

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

            s3_notification = {"Records": [record]}

            sqs.send_message(
                QueueUrl=queue_url,
                MessageBody=json.dumps(s3_notification),
            )

            logger.info(
                f"S3 notification forwarded to {queue_label} queue for: "
                f"s3://{bucket}/{key}"
            )

    except Exception as e:
        logger.exception("Error processing file")
        return {"statusCode": 500, "body": f"Error: {str(e)}"}

    return {"statusCode": 200, "body": "Processing complete"}
