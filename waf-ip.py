import gzip
import json
import logging
import os
import sys
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

COMPLIANT_ACCOUNT_NUMBERS = [account.strip() for account in os.environ["US_COMPLIANT_ACCOUNTS"].split(",")]
EVENT_NAME_EXCLUDED_LIST = list(os.environ["EVENT_NAME_EXCLUDED_LIST"].split(","))
EVENT_ROLE_ARN_EXCLUDED_LIST = list(os.environ["EVENT_ROLE_ARN_EXCLUDED_LIST"].split(","))

MAX_RECORD_SIZE = 1000000  # 1MB Firehose limit


def check_compliant_account(key):
    """Check if the S3 key contains a compliant account number"""
    return any(account in key for account in COMPLIANT_ACCOUNT_NUMBERS)


def check_event_excluded(data):
    """Check if event should be excluded based on event name and role ARN"""
    roles_list = []
    if data.get("eventName") in EVENT_NAME_EXCLUDED_LIST:
        roles_list.append(data.get('userIdentity', {}).get('sessionContext', {}).get('sessionIssuer', {}).get('arn'))
        roles_list.append(data.get('userIdentity', {}).get('arn'))
        if isinstance(data.get('resources'), list):
            for i in data.get('resources'):
                if isinstance(i, dict) and "ARN" in i:
                    roles_list.append(i.get("ARN"))
        for i in roles_list:
            if isinstance(i, str):
                for j in EVENT_ROLE_ARN_EXCLUDED_LIST:
                    if i.endswith(j):
                        return True
    return False


def filter_cloudtrail_events(data):
    """Filter CloudTrail events and remove excluded events, returns batched arrays"""
    batches = []
    current_batch = []
    current_batch_size = 0
    
    if "Records" not in data:
        return batches
    
    for record in data.get("Records"):
        record_json = json.dumps(record)
        record_size = len(record_json.encode('utf-8'))
        
        # Skip oversized individual records
        if record_size > MAX_RECORD_SIZE:
            logger.warning("Record size exceeds 1MB, skipping")
            continue
        
        # Skip excluded events
        if check_event_excluded(record):
            continue
        
        # If adding this record exceeds limit, start new batch
        if current_batch_size + record_size > MAX_RECORD_SIZE and current_batch:
            batches.append(current_batch)
            current_batch = []
            current_batch_size = 0
        
        current_batch.append(record)
        current_batch_size += record_size
    
    # Add remaining records
    if current_batch:
        batches.append(current_batch)
    
    return batches


def parse_gzip_log_file(s3, key, bucket):
    """Parse gzipped CloudTrail log file from S3"""
    response = s3.get_object(Bucket=bucket, Key=key)
    with gzip.GzipFile(fileobj=response.get("Body")) as file:
        return json.loads(file.read().decode("UTF-8"))


def lambda_handler(event, context):
    logger.info("Starting processing CloudTrail logs")
    try:
        s3 = boto3.client('s3', region_name=os.environ["REGION_NAME"])
        firehose = boto3.client('firehose')
        
        bucket = event.get("Records")[0].get("s3").get("bucket").get("name")
        key = event.get("Records")[0].get("s3").get("object").get("key")
        
        content = parse_gzip_log_file(s3=s3, key=key, bucket=bucket)
        
        if not content or not isinstance(content, dict):
            raise Exception("Cannot unpack CloudTrail logs")
        
        # Returns array of batches: [[batch1_records], [batch2_records], ...]
        batches = filter_cloudtrail_events(data=content)
        
        if batches:
            stream_name = "Google-SecOps-Cloudtrail-Compliant-Put" if check_compliant_account(key) else "Google-SecOps-Cloudtrail-Put"
            
            total_records = 0
            for batch in batches:
                firehose.put_record(
                    DeliveryStreamName=stream_name,
                    Record={'Data': json.dumps({"Records": batch})}
                )
                total_records += len(batch)
            
            logger.info(f"Sent {total_records} records in {len(batches)} batches to {stream_name}")
        else:
            logger.warning("No records to process after filtering")
        
        return {
            'statusCode': 200,
            'body': 'Processing complete'
        }
            
    except Exception as error:
        logger.exception(error)
        return {
            'statusCode': 500,
            'body': f'Processing failed: {str(error)}'
        }
