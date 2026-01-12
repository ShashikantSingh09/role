import json
import gzip
import base64
import urllib.request
import urllib.parse
import os
import logging
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    Receives CloudWatch Logs subscription events,
    converts them to Chronicle AWS_WAF format,
    and pushes them to Google SecOps via HTTPS webhook.
    """

    if "awslogs" not in event or "data" not in event["awslogs"]:
        logger.info("Not a CloudWatch Logs event. Ignoring.")
        return {
            "statusCode": 200,
            "body": "Not a CloudWatch Logs event"
        }

    base_url = os.environ.get("GOOGLE_SECOPS_WEBHOOK_URL")
    api_key = os.environ.get("GOOGLE_SECOPS_API_KEY")
    feed_secret = os.environ.get("GOOGLE_SECOPS_FEED_SECRET")

    if not base_url or not api_key or not feed_secret:
        logger.error("Missing Chronicle environment variables")
        return {
            "statusCode": 500,
            "body": "Missing environment variables"
        }

    params = urllib.parse.urlencode({
        "key": api_key,
        "secret": feed_secret
    })
    webhook_url = f"{base_url}?{params}"

    try:
        compressed_data = base64.b64decode(event["awslogs"]["data"])
        decompressed_data = gzip.decompress(compressed_data)
        logs_payload = json.loads(decompressed_data)

        log_events = logs_payload.get("logEvents", [])
        if not log_events:
            logger.info("No log events in payload")
            return {
                "statusCode": 200,
                "body": "No log events"
            }

        log_group = logs_payload.get("logGroup")
        log_stream = logs_payload.get("logStream")

        batch = []

        for log in log_events:
            # Convert timestamp to RFC3339 (Chronicle-friendly)
            ts_ms = log.get("timestamp")
            timestamp = (
                datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
                .isoformat()
                if ts_ms else None
            )

            batch.append({
                "log_type": "AWS_WAF",
                "timestamp": timestamp,
                "jsonPayload": {
                    "message": log.get("message"),
                    "logGroup": log_group,
                    "logStream": log_stream,
                    "awsRegion": os.environ.get("AWS_REGION"),
                    "functionArn": context.invoked_function_arn
                }
            })

        payload_bytes = json.dumps(batch).encode("utf-8")

        request = urllib.request.Request(
            webhook_url,
            data=payload_bytes,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "aws-cloudwatch-waf-forwarder"
            },
            method="POST"
        )

        with urllib.request.urlopen(request, timeout=10) as response:
            logger.info(
                "Forwarded %d AWS_WAF events to Chronicle. HTTP %s",
                len(batch),
                response.status
            )
            return {
                "statusCode": response.status,
                "body": f"Forwarded {len(batch)} AWS_WAF events"
            }

    except Exception as exc:
        logger.exception("Failed to process or send logs")
        return {
            "statusCode": 500,
            "body": str(exc)
        }
