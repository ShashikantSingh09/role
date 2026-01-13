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

SECOPS_TIMEOUT = 10

def lambda_handler(event, context):
    """
    CloudWatch Logs → Google SecOps (Chronicle)
    Feed type: HTTPS_PUSH_WEBHOOK
    Source: AWS_CLOUDWATCH
    """
    if not isinstance(event, dict) or 'awslogs' not in event or 'data' not in event.get('awslogs', {}):
        logger.info("Not a CloudWatch Logs subscription event. Ignored.")
        return {"statusCode": 200, "body": "Ignored non-CloudWatch event"}

    base_url = os.environ.get("GOOGLE_SECOPS_WEBHOOK_URL")
    api_key = os.environ.get("GOOGLE_SECOPS_API_KEY")
    feed_secret = os.environ.get("GOOGLE_SECOPS_FEED_SECRET")

    if not base_url or not api_key or not feed_secret:
        logger.error("Missing Google SecOps environment variables")
        return {"statusCode": 500, "body": "Missing env vars"}

    params = urllib.parse.urlencode({
        "key": api_key,
        "secret": feed_secret
    })
    secops_url = f"{base_url}?{params}"

    try:
        compressed = base64.b64decode(event["awslogs"]["data"])
        decompressed = gzip.decompress(compressed)
        payload = json.loads(decompressed)

        log_events = payload.get("logEvents", [])
        if not log_events:
            logger.info("No logEvents found")
            return {"statusCode": 200, "body": "No log events"}

        sent = 0
        failed = 0

        for log in log_events:
            event_time = datetime.fromtimestamp(
                log["timestamp"] / 1000,
                tz=timezone.utc
            ).isoformat()

            secops_event = {
                "eventTime": event_time,
                "message": log.get("message"),
                "logGroup": payload.get("logGroup"),
                "logStream": payload.get("logStream"),
                "source": "aws-cloudwatch",
                "severity": "INFO",
                "awsRegion": os.environ.get("AWS_REGION"),
                "functionArn": context.invoked_function_arn,
                "requestId": context.aws_request_id
            }

            data = json.dumps(secops_event).encode("utf-8")

            request = urllib.request.Request(
                secops_url,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "aws-cloudwatch-secops-forwarder"
                },
                method="POST"
            )

            try:
                with urllib.request.urlopen(request, timeout=SECOPS_TIMEOUT) as response:
                    logger.info("Sent log to SecOps, HTTP %s", response.status)
                    sent += 1
            except Exception as send_err:
                logger.error(
                    "FAILED sending log to SecOps: %s | Payload: %s",
                    send_err,
                    json.dumps(secops_event)
                )
                failed += 1

        logger.info("SecOps delivery complete | sent=%d failed=%d", sent, failed)
        return {
            "statusCode": 200 if failed == 0 else 207,
            "body": f"Sent={sent}, Failed={failed}"
        }

    except Exception as exc:
        logger.exception("Fatal error processing CloudWatch Logs")
        return {"statusCode": 500, "body": str(exc)}
