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

MAX_RECORD_SIZE = 1000000


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
    """Filter CloudTrail events and remove excluded events"""
    filtered_records = []
    if "Records" not in data:
        return filtered_records
    
    for record in data.get("Records"):
        if sys.getsizeof(record) > MAX_RECORD_SIZE:
            logger.warning("Record size exceeds 1,000 KiB, skipping")
            continue
        if not check_event_excluded(record):
            filtered_records.append(record)
    
    return filtered_records


def parse_gzip_log_file(s3, key, bucket):
    """Parse gzipped CloudTrail log file from S3"""
    response = s3.get_object(Bucket=bucket, Key=key)
    with gzip.GzipFile(fileobj=response.get("Body")) as file:
        return json.loads(file.read().decode("UTF-8"))


def send_to_firehose(firehose, stream_name, records):
    """Send records to Firehose in batches to stay under 1MB limit"""
    batch = []
    batch_size = 0
    
    for record in records:
        record_size = len(json.dumps(record).encode('utf-8'))
        
        if batch_size + record_size > MAX_RECORD_SIZE and batch:
            firehose.put_record(
                DeliveryStreamName=stream_name,
                Record={'Data': json.dumps({"Records": batch})}
            )
            batch = []
            batch_size = 0
        
        batch.append(record)
        batch_size += record_size
    
    if batch:
        firehose.put_record(
            DeliveryStreamName=stream_name,
            Record={'Data': json.dumps({"Records": batch})}
        )


def lambda_handler(event, context):
    logger.info("Starting processing cloudtrail logs")
    try:
        s3 = boto3.client('s3', region_name=os.environ["REGION_NAME"])
        firehose = boto3.client('firehose')
        
        bucket = event.get("Records")[0].get("s3").get("bucket").get("name")
        key = event.get("Records")[0].get("s3").get("object").get("key")
        
        content = parse_gzip_log_file(s3=s3, key=key, bucket=bucket)
        
        if not content or not isinstance(content, dict):
            raise Exception("Cannot unpack cloudtrail logs")
        
        filtered_records = filter_cloudtrail_events(data=content)
        
        if filtered_records:
            if check_compliant_account(key):
                send_to_firehose(firehose, "Google-SecOps-Cloudtrail-Compliant-Put", filtered_records)
                logger.info("Filtered FedRAMP/GovCloud CloudTrail logs sent to Google SecOps")
            else:
                send_to_firehose(firehose, "Google-SecOps-Cloudtrail-Put", filtered_records)
                logger.info("Filtered CloudTrail logs sent to Google SecOps")
        else:
            logger.warning("No records to process after filtering")
            
    except Exception as error:
        logger.exception(error)
    
    return {
        'statusCode': 200,
        'body': 'Processing complete'
    }
