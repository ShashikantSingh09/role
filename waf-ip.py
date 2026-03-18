import gzip
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

MAX_SQS_SIZE = 262144 

s3 = boto3.client("s3", region_name=REGION_NAME)
sqs = boto3.client("sqs", region_name=REGION_NAME)


def check_compliant_account(key):
    return any(account.strip() in key for account in US_COMPLIANT_ACCOUNTS)


def lambda_handler(event, context):
    logger.info("Starting CloudTrail log forwarding to Google SecOps")

    try:
        if not event.get("Records"):
            logger.error("No Records found in event")
            return {"statusCode": 400, "body": "Invalid event format"}

        for record in event["Records"]:
            bucket = record["s3"]["bucket"]["name"]
            key = urllib.parse.unquote(record["s3"]["object"]["key"])
            )

            logger.info(f"Processing: s3://{bucket}/{key}")

            if not key.endswith(".json.gz"):
                logger.info(f"Skipping non-CloudTrail file: {key}")
                continue

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

            response = s3.get_object(Bucket=bucket, Key=key)
            compressed_data = response["Body"].read()

            # Decompress gzip to get raw CloudTrail JSON
            raw_json = gzip.decompress(compressed_data).decode("utf-8")

            logger.info(
                f"Decompressed CloudTrail log: {len(raw_json)} bytes "
                f"from s3://{bucket}/{key}"
            )

            if len(raw_json.encode("utf-8")) > MAX_SQS_SIZE:
                logger.warning(
                    f"File exceeds SQS 256KB limit ({len(raw_json)} bytes). "
                    f"Splitting individual CloudTrail records."
                )
                ct_data = json.loads(raw_json)
                ct_records = ct_data.get("Records", [])

                for i, ct_record in enumerate(ct_records):
                    single_record = json.dumps({"Records": [ct_record]})

                    if len(single_record.encode("utf-8")) > MAX_SQS_SIZE:
                        logger.error(
                            f"Single CloudTrail record {i} exceeds 256KB, skipping"
                        )
                        continue

                    sqs.send_message(
                        QueueUrl=queue_url,
                        MessageBody=single_record,
                    )

                logger.info(
                    f"Sent {len(ct_records)} individual records to "
                    f"{queue_label} queue"
                )
            else:
                sqs.send_message(
                    QueueUrl=queue_url,
                    MessageBody=raw_json,
                )

                logger.info(
                    f"CloudTrail log sent to {queue_label} queue: "
                    f"s3://{bucket}/{key}"
                )

    except Exception as e:
        logger.exception("Error processing file")
        return {"statusCode": 500, "body": f"Error: {str(e)}"}

    return {"statusCode": 200, "body": "Processing complete"}
