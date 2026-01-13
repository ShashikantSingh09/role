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
    
    Fixes:
    1. Uses "message" key (matches your working curl).
    2. Batches logs into a single HTTP POST (prevents timeouts).
    """

    if (
        not isinstance(event, dict)
        or "awslogs" not in event
        or "data" not in event.get("awslogs", {})
    ):
        logger.info("Non-CloudWatch event received. Ignored.")
        return {"statusCode": 200, "body": "Ignored"}

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
            logger.info("No log events found")
            return {"statusCode": 200, "body": "No logs"}

        batch_payload = []

        for log in log_events:
            raw_message = log.get("message", "")
            if not raw_message:
                continue

            event_time = datetime.fromtimestamp(
                log["timestamp"] / 1000,
                tz=timezone.utc
            ).isoformat()

            secops_event = {
                "message": raw_message,
                "timestamp": event_time
            }
            
            batch_payload.append(secops_event)

        if not batch_payload:
            return {"statusCode": 200, "body": "No valid logs to send"}

        data = json.dumps(batch_payload).encode("utf-8")

        request = urllib.request.Request(
            secops_url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "aws-cloudwatch-secops-forwarder"
            },
            method="POST"
        )

        urllib.request.urlopen(request, timeout=SECOPS_TIMEOUT)
        
        count = len(batch_payload)
        logger.info(f"Successfully sent batch of {count} logs to SecOps.")

        return {
            "statusCode": 200,
            "body": f"Sent batch of {count} logs"
        }

    except urllib.error.HTTPError as e:
        logger.error(f"HTTP Error {e.code}: {e.read().decode('utf-8')}")
        return {"statusCode": e.code, "body": str(e)}
    except Exception as exc:
        logger.exception("Fatal error processing CloudWatch Logs")
        return {"statusCode": 500, "body": str(exc)}
