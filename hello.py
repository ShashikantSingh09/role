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

    if "awslogs" not in event or "data" not in event["awslogs"]:
        return {"statusCode": 200, "body": "Ignored"}

    base_url = os.environ.get("GOOGLE_SECOPS_WEBHOOK_URL")
    api_key = os.environ.get("GOOGLE_SECOPS_API_KEY")
    feed_secret = os.environ.get("GOOGLE_SECOPS_FEED_SECRET")

    if not all([base_url, api_key, feed_secret]):
        logger.error("Missing env vars")
        return {"statusCode": 500}

    secops_url = f"{base_url}?{urllib.parse.urlencode({'key': api_key, 'secret': feed_secret})}"

    try:
        compressed = base64.b64decode(event["awslogs"]["data"])
        payload = json.loads(gzip.decompress(compressed))

        events = []
        for log in payload.get("logEvents", []):
            if not log.get("message"):
                continue

            events.append({
                "message": log["message"],  # Unicode allowed
                "timestamp": datetime.fromtimestamp(
                    log["timestamp"] / 1000, tz=timezone.utc
                ).isoformat(),
                "logGroup": payload.get("logGroup"),
                "logStream": payload.get("logStream"),
                "eventId": log.get("id")
            })

        if not events:
            return {"statusCode": 200, "body": "No logs"}

        body = json.dumps(
            {"events": events},
            ensure_ascii=False
        ).encode("utf-8")

        request = urllib.request.Request(
            secops_url,
            data=body,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": "aws-cloudwatch-secops-forwarder"
            },
            method="POST"
        )

        urllib.request.urlopen(request, timeout=SECOPS_TIMEOUT)

        logger.info("Sent %d events to SecOps", len(events))
        return {"statusCode": 200, "body": f"Sent {len(events)}"}

    except Exception:
        logger.exception("Fatal error sending logs to SecOps")
        return {"statusCode": 500}
