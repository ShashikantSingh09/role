import json
import gzip
import base64
import urllib.request
import urllib.parse
import os
import logging

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    Decodes CloudWatch logs and forwards them to Google SecOps (Chronicle)
    using credentials from environment variables.
    """
    base_url = os.environ.get('GOOGLE_SECOPS_WEBHOOK_URL')
    api_key = os.environ.get('GOOGLE_SECOPS_API_KEY')
    feed_secret = os.environ.get('GOOGLE_SECOPS_FEED_SECRET')

    if not base_url or not api_key or not feed_secret:
        logger.error("Missing required environment variables (URL, API Key, or Secret).")
        return

    # Construct the authenticated URL
    # Google SecOps Webhooks typically use query params: ?key=API_KEY&secret=SECRET
    params = urllib.parse.urlencode({'key': api_key, 'secret': feed_secret})
    authenticated_url = f"{base_url}?{params}"

    try:
        # 1. Decode and decompress CloudWatch logs
        cw_data = event['awslogs']['data']
        compressed_payload = base64.b64decode(cw_data)
        uncompressed_payload = gzip.decompress(compressed_payload)
        payload = json.loads(uncompressed_payload)
        
        log_events = payload.get('logEvents', [])
        
        # 2. Prepare the batch
        batch_entries = []
        for log in log_events:
            entry = {
                "timestamp": log['timestamp'],
                "message": log['message'],
                "logGroup": payload.get('logGroup'),
                "logStream": payload.get('logStream'),
                "function_arn": context.invoked_function_arn,
                "aws_request_id": context.aws_request_id
            }
            batch_entries.append(entry)

        if not batch_entries:
            return {'statusCode': 200, 'body': 'No log events found.'}

        # 3. Send to Google SecOps
        data = json.dumps(batch_entries).encode('utf-8')
        
        req = urllib.request.Request(
            authenticated_url, 
            data=data, 
            headers={
                'Content-Type': 'application/json',
                'User-Agent': 'AWS-Lambda-CloudWatch-Forwarder'
            }
        )
        
        with urllib.request.urlopen(req) as response:
            logger.info(f"Successfully sent {len(batch_entries)} logs. Response: {response.status}")
            return {
                'statusCode': response.status,
                'body': f"Forwarded {len(batch_entries)} logs."
            }

    except Exception as e:
        logger.error(f"Error processing logs: {str(e)}")
        raise e