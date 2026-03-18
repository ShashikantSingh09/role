import json
import logging
import os
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


def lambda_handler(event, context):

    logger.info("Received S3 event")
    logger.info(json.dumps(event))

    sqs = boto3.client("sqs", region_name=REGION_NAME)

    try:
        for record in event.get("Records", []):

            key = record["s3"]["object"]["key"]
            account_id = get_account_id_from_key(key)

            # Decide queue
            if account_id in US_COMPLIANT_ACCOUNTS:
                queue_url = US_COMPLIANT_QUEUE_URL
                queue_label = "US_COMPLIANT"
            else:
                queue_url = NON_US_COMPLIANT_QUEUE_URL
                queue_label = "NON_US_COMPLIANT"

            logger.info(f"Routing to {queue_label}")

            message_body = json.dumps({
                "Records": [record]
            })

            logger.info(f"SQS Message Body: {message_body}")

            response = sqs.send_message(
                QueueUrl=queue_url,
                MessageBody=message_body
            )

            logger.info(f"Message sent. ID: {response['MessageId']}")

    except Exception as e:
        logger.exception("Error processing event")
        return {"statusCode": 500, "body": str(e)}

    return {"statusCode": 200, "body": "Success"}
