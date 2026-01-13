import json
import gzip
import base64
import urllib.request
import urllib.parse
import os
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SECOPS_TIMEOUT = 10

def lambda_handler(event, context):
    """
    CloudWatch Logs → Google SecOps (Chronicle)
    
    Updated Logic:
    - Unzips the CloudWatch payload.
    - Iterates through log events.
    - Sends the RAW 'message' field directly to SecOps (stripping AWS metadata).
    """
    # 1. Basic Validation
    if not isinstance(event, dict) or 'awslogs' not in event or 'data' not in event.get('awslogs', {}):
        logger.info("Not a CloudWatch Logs subscription event. Ignored.")
        return {"statusCode": 200, "body": "Ignored non-CloudWatch event"}

    # 2. Setup Configuration
    base_url = os.environ.get("GOOGLE_SECOPS_WEBHOOK_URL")
    api_key = os.environ.get("GOOGLE_SECOPS_API_KEY")
    feed_secret = os.environ.get("GOOGLE_SECOPS_FEED_SECRET")

    if not base_url or not api_key or not feed_secret:
        logger.error("Missing Google SecOps environment variables")
        return {"statusCode": 500, "body": "Missing env vars"}

    # 3. Build URL with Authentication
    params = urllib.parse.urlencode({
        "key": api_key,
        "secret": feed_secret
    })
    secops_url = f"{base_url}?{params}"

    try:
        # 4. Decompress CloudWatch Data
        compressed = base64.b64decode(event["awslogs"]["data"])
        decompressed = gzip.decompress(compressed)
        payload = json.loads(decompressed)

        log_events = payload.get("logEvents", [])
        if not log_events:
            logger.info("No logEvents found")
            return {"statusCode": 200, "body": "No log events"}

        sent = 0
        failed = 0

        # 5. Send Logs
        for log in log_events:
            # FIX: Extract only the raw message content
            raw_message = log.get("message", "")

            # Ensure data is bytes for the request
            if isinstance(raw_message, (dict, list)):
                # If the log message itself is JSON, dump it to string first
                data = json.dumps(raw_message).encode("utf-8")
            else:
                # If it's a string (common for app logs), encode directly
                data = str(raw_message).encode("utf-8")

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
                    # Optional: Log success only for debugging to reduce noise
                    # logger.info("Sent log to SecOps, HTTP %s", response.status)
                    sent += 1
            except Exception as send_err:
                logger.error(
                    "FAILED sending log to SecOps: %s",
                    send_err
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
