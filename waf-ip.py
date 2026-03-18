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
    try:
        return key.split("/")[1]
    except Exception:
        return None


def is_compliant_account(account_id):
    return account_id in US_COMPLIANT_ACCOUNTS


def lambda_handler(event, context):

    logger.info("Received S3 event")
    logger.info(json.dumps(event))

    sqs = boto3.client("sqs", region_name=REGION_NAME)

    for record in event["Records"]:

        bucket = record["s3"]["bucket"]["name"]
        key = urllib.parse.unquote_plus(record["s3"]["object"]["key"])

        account_id = get_account_id_from_key(key)

        queue_url = (
            US_COMPLIANT_QUEUE_URL
            if account_id and is_compliant_account(account_id)
            else NON_US_COMPLIANT_QUEUE_URL
        )

        queue_label = (
            "US_COMPLIANT"
            if queue_url == US_COMPLIANT_QUEUE_URL
            else "NON_US_COMPLIANT"
        )

        logger.info(f"Routing to {queue_label}")

        message_body = json.dumps({
            "Records": [record]
        })

        response = sqs.send_message(
            QueueUrl=queue_url,
            MessageBody=message_body
        )

        logger.info(f"Sent message ID: {response['MessageId']}")

    return {
        "statusCode": 200,
        "body": "Success"
    }
