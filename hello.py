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
    Extract account ID from CloudTrail S3 path:
    AWSLogs/<ACCOUNT_ID>/CloudTrail/...
    """
    try:
        return key.split("/")[1]
    except Exception:
        logger.warning(f"Could not extract account ID from key: {key}")
        return None


def is_compliant(account_id):
    return account_id in US_COMPLIANT_ACCOUNTS


def lambda_handler(event, context):

    logger.info("Received S3 event")

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

            account_id = get_account_id_from_key(key)

            if account_id:
                logger.info(f"Account ID extracted: {account_id}")
            else:
                logger.warning("Account ID not found, defaulting to NON_COMPLIANT")

            queue_url = (
                US_COMPLIANT_QUEUE_URL
                if account_id and is_compliant(account_id)
                else NON_US_COMPLIANT_QUEUE_URL
            )

            queue_label = (
                "US_COMPLIANT"
                if queue_url == US_COMPLIANT_QUEUE_URL
                else "NON_US_COMPLIANT"
            )

            logger.info(f"Sending to queue: {queue_label}")

            response = sqs.send_message(
                QueueUrl=queue_url,
                MessageBody=s3_uri
            )

            logger.info(f"Message sent successfully. MessageId: {response['MessageId']}")

    except Exception as e:
        logger.exception("Error processing event")
        return {"statusCode": 500, "body": str(e)}

    return {"statusCode": 200, "body": "Processing complete"}
