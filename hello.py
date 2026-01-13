import json
import gzip
import base64
import os
import logging
from datetime import datetime, timezone
from http.client import HTTPSConnection
from urllib.parse import urlparse, urlencode, quote

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SECOPS_TIMEOUT = 10


def lambda_handler(event, context):

    if "awslogs" not in event or "data" not in event["awslogs"]:
        return {"statusCode": 200, "body": "Ignored"}

    base_url = os.environ["GOOGLE_SECOPS_WEBHOOK_URL"]
    api_key = os.environ["GOOGLE_SECOPS_API_KEY"]
    feed_secret = os.environ["GOOGLE_SECOPS_FEED_SECRET"]

    parsed = urlparse(base_url)

    # 🔧 FORCE ASCII-SAFE QUERY STRING
    query = urlencode(
        {"key": api_key, "secret": feed_secret},
        safe=""
    )

    # 🔧 FORCE ASCII-SAFE PATH
    path = quote(parsed.path or "/", safe="/") + "?" + query

    try:
        payload = json.loads(
            gzip.decompress(base64.b64decode(event["awslogs"]["data"]))
        )

        events = []
        for log in payload.get("logEvents", []):
            if not log.get("message"):
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
            return {"statusCode": 200, "body": "No logs"}

        body = json.dumps(
            {"events": events},
            ensure_ascii=False
        ).encode("utf-8")
        host = parsed.hostname.encode("idna").decode("ascii")

        conn = HTTPSConnection(host, timeout=SECOPS_TIMEOUT)
        conn.request(
            "POST",
            path,
            body=body,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": "aws-cloudwatch-secops-forwarder"
            }
        )

        resp = conn.getresponse()
        resp.read()
        conn.close()

        logger.info("Sent %d events to SecOps", len(events))
        return {"statusCode": resp.status}

    except Exception:
        logger.exception("Fatal error sending logs to SecOps")
        return {"statusCode": 500}
