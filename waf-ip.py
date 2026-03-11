import logging
import os
import boto3
import base64

logger = logging.getLogger()
logger.setLevel(logging.INFO)

US_COMPLIANT_ACCOUNTS = os.environ["US_COMPLIANT_ACCOUNTS"].split(",")
US_COMPLIANT_QUEUE_URL = os.environ["US_COMPLIANT_QUEUE_URL"]
NON_US_COMPLIANT_QUEUE_URL = os.environ["NON_US_COMPLIANT_QUEUE_URL"]
REGION_NAME = os.environ["REGION_NAME"]

MAX_SQS_SIZE = 262144  # 256 KB


def check_compliant_account(key):
    """
    Check if the S3 object key belongs to a US compliant account
    """
    return any(account.strip() in key for account in US_COMPLIANT_ACCOUNTS)


def lambda_handler(event, context):
    logger.info("Starting raw CloudTrail forwarding")

    try:
        if not event.get("Records"):
            return {
                "statusCode": 400,
                "body": "Invalid event format"
            }

        s3 = boto3.client("s3", region_name=REGION_NAME)
        sqs = boto3.client("sqs")

        bucket = event["Records"][0]["s3"]["bucket"]["name"]
        key = event["Records"][0]["s3"]["object"]["key"]

        logger.info(f"Fetching object {key} from bucket {bucket}")

        response = s3.get_object(Bucket=bucket, Key=key)
        file_content = response["Body"].read()

        if len(file_content) > MAX_SQS_SIZE:
            logger.error("File exceeds SQS 256KB limit")
            return {
                "statusCode": 400,
                "body": "File too large for SQS"
            }

        encoded_content = base64.b64encode(file_content).decode("utf-8")

        queue_url = (
            US_COMPLIANT_QUEUE_URL
            if check_compliant_account(key)
            else NON_US_COMPLIANT_QUEUE_URL
        )

        sqs.send_message(
            QueueUrl=queue_url,
            MessageBody=encoded_content
        )

        logger.info("Raw .json.gz file sent to SQS successfully")

    except Exception as e:
        logger.exception("Error processing file")

    return {
        "statusCode": 200,
        "body": "Processing complete"
    }
