import json
import gzip
import base64
import urllib.request
import urllib.parse
import os
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    Decodes CloudWatch Logs subscription events and forwards them
    to Google SecOps (Chronicle). Safely ignores non-logs invocations.
    """

    if 'awslogs' not in event or 'data' not in event.get('awslogs', {}):
        logger.info("Invocation is not from CloudWatch Logs. Ignoring event.")
        return {
            "statusCode": 200,
            "body": "Not a CloudWatch Logs event"
        }

    base_url = os.environ.get('GOOGLE_SECOPS_WEBHOOK_URL')
    api_key = os.environ.get('GOOGLE_SECOPS_API_KEY')
    feed_secret = os.environ.get('GOOGLE_SECOPS_FEED_SECRET')

    if not base_url or not api_key or not feed_secret:
        logger.error("Missing required environment variables.")
        return {
            "statusCode": 500,
            "body": "Missing environment variables"
        }

    # Chronicle webhook uses query parameters
    params = urllib.parse.urlencode({
        'key': api_key,
        'secret': feed_secret
    })
    authenticated_url = f"{base_url}?{params}"

    try:
        compressed_data = base64.b64decode(event['awslogs']['data'])
        decompressed_data = gzip.decompress(compressed_data)
        logs_payload = json.loads(decompressed_data)

        log_events = logs_payload.get('logEvents', [])
        if not log_events:
            logger.info("No log events found in payload.")
            return {
                "statusCode": 200,
                "body": "No log events"
            }

        # 2️⃣ Build Chronicle-compatible batch
        batch = []
        for log in log_events:
            batch.append({
                "timestamp": log.get("timestamp"),
                "message": log.get("message"),
                "logGroup": logs_payload.get("logGroup"),
                "logStream": logs_payload.get("logStream"),
                "awsRegion": os.environ.get("AWS_REGION"),
                "functionArn": context.invoked_function_arn,
                "requestId": context.aws_request_id
            })

        payload_bytes = json.dumps(batch).encode("utf-8")

        request = urllib.request.Request(
            authenticated_url,
            data=payload_bytes,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "aws-cloudwatch-log-forwarder"
            },
            method="POST"
        )

        with urllib.request.urlopen(request, timeout=10) as response:
            logger.info(
                "Forwarded %d log events. Chronicle response: %s",
                len(batch),
                response.status
            )
            return {
                "statusCode": response.status,
                "body": f"Forwarded {len(batch)} log events"
            }

    except Exception as exc:
        logger.exception("Failed to process CloudWatch Logs event")
        return {
            "statusCode": 500,
            "body": str(exc)
        }
