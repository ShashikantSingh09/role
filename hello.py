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
MAX_BATCH_SIZE = 1000


def lambda_handler(event, context):
    """
    CloudWatch Logs → Google SecOps (Chronicle)
    Log Type: CloudWatch
    Transport: HTTPS Push
    """

    if "awslogs" not in event or "data" not in event["awslogs"]:
        logger.info("Ignored non-CloudWatch event")
        return {"statusCode": 200, "body": "Ignored"}

    base_url = os.environ.get("GOOGLE_SECOPS_WEBHOOK_URL")
    api_key = os.environ.get("GOOGLE_SECOPS_API_KEY")
    feed_secret = os.environ.get("GOOGLE_SECOPS_FEED_SECRET")

    if not all([base_url, api_key, feed_secret]):
        logger.error("Missing SecOps environment variables")
        return {"statusCode": 500, "body": "Missing env vars"}

    secops_url = f"{base_url}?{urllib.parse.urlencode({'key': api_key, 'secret': feed_secret})}"

    try:
        compressed = base64.b64decode(event["awslogs"]["data"])
        decompressed = gzip.decompress(compressed)
        payload = json.loads(decompressed)

        log_events = payload.get("logEvents", [])
        if not log_events:
            return {"statusCode": 200, "body": "No logs"}

        events = []

        for log in log_events:
            if "message" not in log:
                continue

            events.append({
                "message": log["message"],
                "timestamp": datetime.fromtimestamp(
                    log["timestamp"] / 1000, tz=timezone.utc
                ).isoformat(),
                "logGroup": payload.get("logGroup"),
                "logStream": payload.get("logStream"),
                "eventId": log.get("id")
            })

        if not events:
            return {"statusCode": 200, "body": "No valid logs"}

        body = json.dumps({"events": events}).encode("utf-8")

        request = urllib.request.Request(
            secops_url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "aws-cloudwatch-secops-forwarder"
            },
            method="POST"
        )

        urllib.request.urlopen(request, timeout=SECOPS_TIMEOUT)

        logger.info("Sent %d events to SecOps", len(events))
        return {"statusCode": 200, "body": f"Sent {len(events)} events"}

    except Exception:
        logger.exception("Fatal error sending logs to SecOps")
        return {"statusCode": 500, "body": "Processing error"}
