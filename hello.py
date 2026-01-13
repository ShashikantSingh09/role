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

    ✔ HTTPS_PUSH_WEBHOOK
    ✔ AWS_CLOUDWATCH source
    ✔ Default AWS parsers compatible
    """

    # ---------- Guard: Only CloudWatch Logs ----------
    if (
        not isinstance(event, dict)
        or "awslogs" not in event
        or "data" not in event.get("awslogs", {})
    ):
        logger.info("Non-CloudWatch event received. Ignored.")
        return {"statusCode": 200, "body": "Ignored"}

    # ---------- Environment ----------
    base_url = os.environ.get("GOOGLE_SECOPS_WEBHOOK_URL")
    api_key = os.environ.get("GOOGLE_SECOPS_API_KEY")
    feed_secret = os.environ.get("GOOGLE_SECOPS_FEED_SECRET")

    if not base_url or not api_key or not feed_secret:
        logger.error("Missing Google SecOps environment variables")
        return {"statusCode": 500, "body": "Missing env vars"}

    # ---------- Authenticated URL ----------
    params = urllib.parse.urlencode({
        "key": api_key,
        "secret": feed_secret
    })
    secops_url = f"{base_url}?{params}"

    try:
        # ---------- Decode CloudWatch Logs ----------
        compressed = base64.b64decode(event["awslogs"]["data"])
        decompressed = gzip.decompress(compressed)
        payload = json.loads(decompressed)

        log_events = payload.get("logEvents", [])
        if not log_events:
            logger.info("No log events found")
            return {"statusCode": 200, "body": "No logs"}

        sent = 0
        failed = 0

        # ---------- Send Each Log ----------
        for log in log_events:
            raw_message = log.get("message", "")
            if not raw_message:
                continue

            event_time = datetime.fromtimestamp(
                log["timestamp"] / 1000,
                tz=timezone.utc
            ).isoformat()

            # ✔ Chronicle-compatible payload
            secops_event = {
                "logText": raw_message,
                "timestamp": event_time
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
                urllib.request.urlopen(request, timeout=SECOPS_TIMEOUT)
                sent += 1
            except Exception as err:
                logger.error("Failed to send log: %s", err)
                failed += 1

        logger.info("SecOps send complete | sent=%d failed=%d", sent, failed)

        return {
            "statusCode": 200 if failed == 0 else 207,
            "body": f"Sent={sent}, Failed={failed}"
        }

    except Exception as exc:
        logger.exception("Fatal error processing CloudWatch Logs")
        return {"statusCode": 500, "body": str(exc)}
