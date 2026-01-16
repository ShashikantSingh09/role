import json
import gzip
import base64
import urllib.request
import logging
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SECRET_NAME = "waf-ip-manage-secops-creds"

_cached_secrets = None


def get_secrets():
    """
    Retrieve secrets from AWS Secrets Manager.
    Caches the result to avoid repeated API calls on warm invocations.
    """
    global _cached_secrets

    if _cached_secrets is not None:
        return _cached_secrets

    client = boto3.client("secretsmanager")

    response = client.get_secret_value(SecretId=SECRET_NAME)

    if "SecretString" in response:
        secret_data = json.loads(response["SecretString"])
    else:
        secret_data = json.loads(base64.b64decode(response["SecretBinary"]))

    required_keys = [
        "google_secops_webhook_url",
        "api_key",
        "feed_secret",
    ]

    for key in required_keys:
        if key not in secret_data:
            raise ValueError(f"Missing required key '{key}' in secret")

    _cached_secrets = secret_data
    logger.info("Secrets loaded from Secrets Manager")
    return _cached_secrets


def lambda_handler(event, context):
    """
    Decode CloudWatch Logs subscription events and forward
    them to Google SecOps (Chronicle).
    """

    if (
        not isinstance(event, dict)
        or "awslogs" not in event
        or "data" not in event.get("awslogs", {})
    ):
        logger.info("Not a CloudWatch Logs subscription event. Event ignored.")
        return {
            "statusCode": 200,
            "body": "Ignored non-CloudWatch Logs event",
        }

    try:
        secrets = get_secrets()
        base_url = secrets["google_secops_webhook_url"]
        api_key = secrets["api_key"]
        feed_secret = secrets["feed_secret"]
    except (ValueError, ClientError) as e:
        logger.error("Failed to retrieve secrets: %s", str(e))
        return {
            "statusCode": 500,
            "body": "Failed to retrieve secrets from Secrets Manager",
        }

    try:
        compressed_data = base64.b64decode(event["awslogs"]["data"])
        decompressed_data = gzip.decompress(compressed_data)
        logs_payload = json.loads(decompressed_data)

        log_events = logs_payload.get("logEvents", [])
        if not log_events:
            logger.info("No log events found")
            return {
                "statusCode": 200,
                "body": "No log events",
            }

        batch = []
        for log in log_events:
            batch.append(
                {
                    "timestamp": log.get("timestamp"),
                    "message": log.get("message"),
                    "logGroup": logs_payload.get("logGroup"),
                    "logStream": logs_payload.get("logStream"),
                    "awsRegion": boto3.session.Session().region_name,
                    "functionArn": context.invoked_function_arn,
                    "requestId": context.aws_request_id,
                }
            )

        payload_bytes = json.dumps(batch).encode("utf-8")

        request = urllib.request.Request(
            base_url,
            data=payload_bytes,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "aws-cloudwatch-log-forwarder",

                "X-Goog-Api-Key": api_key,
                "X-Goog-Feed-Secret": feed_secret,
            },
            method="POST",
        )

        with urllib.request.urlopen(request, timeout=10) as response:
            logger.info(
                "Forwarded %d logs, Chronicle response: %s",
                len(batch),
                response.status,
            )
            return {
                "statusCode": response.status,
                "body": f"Forwarded {len(batch)} log events",
            }

    except Exception as exc:
        logger.exception("Failed processing CloudWatch Logs event")
        return {
            "statusCode": 500,
            "body": str(exc),
        }
