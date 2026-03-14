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
    """Check if the S3 key contains a compliant account ID"""
    for account in US_COMPLIANT_ACCOUNTS:
        if account.strip() in key:
            return True
    return False


def lambda_handler(event, context):

    logger.info("Received S3 event: %s", json.dumps(event))

    try:

        sqs = boto3.client("sqs", region_name=REGION_NAME)

        for record in event["Records"]:

            bucket = record["s3"]["bucket"]["name"]
            key = urllib.parse.unquote_plus(record["s3"]["object"]["key"])

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

            # Forward the same S3 event notification
            message_body = json.dumps({
                "Records": [
                    {
                        "s3": {
                            "bucket": {"name": bucket},
                            "object": {"key": key}
                        }
                    }
                ]
            })

            response = sqs.send_message(
                QueueUrl=queue_url,
                MessageBody=message_body
            )

            logger.info(
                f"Message sent to {queue_label} queue. "
                f"MessageId: {response['MessageId']}"
            )

    except Exception as e:
        logger.exception("Error processing event")
        raise e

    return {
        "statusCode": 200,
        "body": "S3 event forwarded to SQS successfully"
    }
