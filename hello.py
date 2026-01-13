#!/usr/bin/env python3
"""
SecOps Webhook Connectivity Test Script

Run this locally or as a Lambda test event to verify your webhook setup.
It sends a test payload and shows the full response for debugging.

Usage:
  Set environment variables and run:
  
  export GOOGLE_SECOPS_WEBHOOK_URL="https://your-secops-endpoint.com/..."
  export GOOGLE_SECOPS_API_KEY="your-api-key"
  export GOOGLE_SECOPS_FEED_SECRET="your-feed-secret"
  python3 test_secops_webhook.py
"""

import json
import urllib.request
import urllib.error
import os
import sys
from datetime import datetime, timezone


def test_webhook():
    """Test the SecOps webhook with a sample CloudWatch payload."""
    
    base_url = os.environ.get("GOOGLE_SECOPS_WEBHOOK_URL")
    api_key = os.environ.get("GOOGLE_SECOPS_API_KEY")
    feed_secret = os.environ.get("GOOGLE_SECOPS_FEED_SECRET")

    if not all([base_url, api_key, feed_secret]):
        print("❌ ERROR: Missing environment variables")
        print("   Required: GOOGLE_SECOPS_WEBHOOK_URL, GOOGLE_SECOPS_API_KEY, GOOGLE_SECOPS_FEED_SECRET")
        sys.exit(1)

    print("=" * 60)
    print("Google SecOps Webhook Test")
    print("=" * 60)
    print(f"URL: {base_url[:50]}...")
    print(f"API Key: {api_key[:10]}...")
    print(f"Feed Secret: {feed_secret[:10]}...")
    print()

    # Build URL with API key
    if "?" not in base_url:
        secops_url = f"{base_url}?key={api_key}"
    else:
        secops_url = f"{base_url}&key={api_key}"

    # Create test payload in native CloudWatch format
    current_timestamp = int(datetime.now(timezone.utc).timestamp() * 1000)
    
    test_payload = {
        "messageType": "DATA_MESSAGE",
        "owner": "123456789012",
        "logGroup": "/aws/lambda/secops-test-function",
        "logStream": f"2025/01/13/[$LATEST]test-{current_timestamp}",
        "subscriptionFilters": ["secops-webhook-test"],
        "logEvents": [
            {
                "id": f"test-event-{current_timestamp}",
                "timestamp": current_timestamp,
                "message": f"[TEST] SecOps webhook connectivity test at {datetime.now(timezone.utc).isoformat()}"
            }
        ]
    }

    print("Test Payload (Native CloudWatch Format):")
    print(json.dumps(test_payload, indent=2))
    print()

    # Test 1: With header authentication (recommended)
    print("-" * 60)
    print("Test 1: Header Authentication (X-Webhook-Access-Key)")
    print("-" * 60)
    
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "secops-webhook-test/1.0",
        "X-Webhook-Access-Key": feed_secret,
    }
    
    result = send_request(secops_url, headers, test_payload)
    print_result(result)

    # Test 2: With query param authentication (alternative)
    print()
    print("-" * 60)
    print("Test 2: Query Parameter Authentication (&secret=)")
    print("-" * 60)
    
    url_with_secret = f"{secops_url}&secret={feed_secret}"
    headers_no_secret = {
        "Content-Type": "application/json",
        "User-Agent": "secops-webhook-test/1.0",
    }
    
    result = send_request(url_with_secret, headers_no_secret, test_payload)
    print_result(result)

    # Test 3: Try wrapped format (your original approach)
    print()
    print("-" * 60)
    print("Test 3: Custom Wrapped Format (Your Original Approach)")
    print("-" * 60)
    
    wrapped_payload = {
        "eventTime": datetime.now(timezone.utc).isoformat(),
        "message": test_payload["logEvents"][0]["message"],
        "logGroup": test_payload["logGroup"],
        "logStream": test_payload["logStream"],
        "source": "aws-cloudwatch",
        "severity": "INFO",
        "awsRegion": "us-east-1",
    }
    
    print("Wrapped Payload:")
    print(json.dumps(wrapped_payload, indent=2))
    
    result = send_request(secops_url, headers, wrapped_payload)
    print_result(result)

    print()
    print("=" * 60)
    print("Next Steps:")
    print("=" * 60)
    print("1. Check which test returned a successful response")
    print("2. Look for your test message in SecOps:")
    print("   - Search > Raw Log Scan: search for 'secops-webhook-test'")
    print("   - Settings > Feeds: check 'Last Event Received' timestamp")
    print("3. If 200 OK but no data in SecOps, try the native format (Test 1)")
    print()


def send_request(url: str, headers: dict, payload: dict) -> dict:
    """Send HTTP POST request and return detailed results."""
    try:
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(url, data=data, headers=headers, method="POST")
        
        with urllib.request.urlopen(request, timeout=30) as response:
            response_body = response.read().decode("utf-8")
            return {
                "success": True,
                "status_code": response.status,
                "headers": dict(response.headers),
                "body": response_body,
            }
            
    except urllib.error.HTTPError as e:
        error_body = ""
        try:
            error_body = e.read().decode("utf-8")
        except:
            pass
        return {
            "success": False,
            "status_code": e.code,
            "reason": e.reason,
            "headers": dict(e.headers) if e.headers else {},
            "body": error_body,
        }
        
    except urllib.error.URLError as e:
        return {
            "success": False,
            "error": f"URL Error: {e.reason}",
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


def print_result(result: dict):
    """Pretty print the test result."""
    if result.get("success"):
        print(f"✅ HTTP {result['status_code']} OK")
    else:
        status = result.get('status_code', 'N/A')
        reason = result.get('reason', result.get('error', 'Unknown'))
        print(f"❌ HTTP {status} - {reason}")
    
    if result.get("headers"):
        print("\nResponse Headers:")
        for k, v in list(result["headers"].items())[:5]:  # First 5 headers
            print(f"  {k}: {v}")
    
    body = result.get("body", "")
    if body:
        print(f"\nResponse Body ({len(body)} bytes):")
        print(f"  {body[:500]}")  # First 500 chars
        
        # Try to parse as JSON for prettier output
        try:
            parsed = json.loads(body)
            if parsed:
                print("\nParsed JSON Response:")
                print(json.dumps(parsed, indent=2)[:500])
        except:
            pass


if __name__ == "__main__":
    test_webhook()
