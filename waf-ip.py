import gzip
import json
import logging
import os
import sys
import boto3
import re

logger = logging.getLogger()

# Predefined list of account numbers to exclude Ensure no white spaces. List is for Fedramp Accounts
EXCLUDED_ACCOUNT_NUMBERS = [account.strip() for account in os.environ["US_COMPLIANT_ACCOUNTS"].split(",")]

EVENT_NAME_EXCLUDED_LIST = list(os.environ["EVENT_NAME_EXCLUDED_LIST"].split(","))
EVENT_ROLE_ARN_EXCLUDED_LIST = list(os.environ["EVENT_ROLE_ARN_EXCLUDED_LIST"].split(","))

MAX_RECORD_BATCH_SIZE = 1000000
MAX_RECORD_BATCH_LENGHT = 500

def check_check_compliant_account(key):

    EVENT_ACCOUNT_FEDGOV_LIST = EXCLUDED_ACCOUNT_NUMBERS
    
    # Check if any element in the list is in the key
    if any(element in key for element in EVENT_ACCOUNT_FEDGOV_LIST):
        return True
    else:
        return False

def check_event_excluded(data):
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

def parse_gzip_log_file(s3, key, bucket):
    response = s3.get_object(Bucket=bucket, Key=key)
    with gzip.GzipFile(fileobj=response.get("Body")) as file:
        return json.loads(file.read().decode("UTF-8"))


def filter_cloudtrail_events(data):
    tmp = []
    results = []
    if "Records" not in data:
        return results
    for i in data.get("Records"):
        if sys.getsizeof(i) > MAX_RECORD_BATCH_SIZE:
            logger.warning("The size of single record is greater than 1,000 KiB")
            continue
        if not check_event_excluded(i):
            # The maximum size of a record sent to Kinesis Data Firehose, before base64-encoding, is 1,000 KiB.
            data = json.dumps((tmp + [i]))
            if sys.getsizeof(data) > MAX_RECORD_BATCH_SIZE:
                results.append(json.dumps(tmp))
                tmp = [i]
            else:
                tmp.append(i)
        if len(tmp) == MAX_RECORD_BATCH_LENGHT:
            results.append(json.dumps(tmp))
            tmp = []
    if tmp:
        results.append(json.dumps(tmp))
    return results


def send_logs_to_firehose(data, firehose_client, stream_name):
    for i in data:
        response = firehose_client.put_record_batch(
            DeliveryStreamName=stream_name,
            Records=[
                {
                    'Data': i
                },
            ]
        )

def lambda_handler(event, context):
    logger.info("Starting processing cloudtrail logs")
    try:
        s3 = boto3.client('s3', region_name=os.environ["REGION_NAME"])
        firehose = boto3.client('firehose')
        bucket = event.get("Records")[0].get("s3").get("bucket").get("name")
        key = event.get("Records")[0].get("s3").get("object").get("key")
        content = parse_gzip_log_file(s3=s3, key=key, bucket=bucket)
        if not content and not isinstance(content, dict):
            raise Exception("Cannot unpack cloudtrail logs")
        data = filter_cloudtrail_events(data=content)
        if data:
            if check_check_compliant_account(key):
                send_logs_to_firehose(data=data, firehose_client=firehose, stream_name=os.environ["US_COMPLIANT_STREAM_NAME"])
                logger.info("FEDRAMP/GOVCLOUD Cloudtrail logs successfully processed")
                # Send raw unfiltered content to Google SecOps for FedRAMP
                firehose.put_record(
                    DeliveryStreamName="Google-SecOps-Cloudtrail-Compliant-Put",
                    Record={'Data': json.dumps(content)}
                )
                logger.info("FedRAMP Cloudtrail logs successfully forwarded to Google SecOps")
            else:
                send_logs_to_firehose(data=data, firehose_client=firehose, stream_name=os.environ["STREAM_NAME"])
                logger.info("Cloudtrail logs successfully processed")
                # Send raw unfiltered content directly to Google SecOps
                firehose.put_record(
                    DeliveryStreamName="Google-SecOps-Cloudtrail-Put",
                    Record={'Data': json.dumps(content)}
                )
                logger.info("Cloudtrail logs successfully forwarded to Google SecOps")
        else:
            logger.warning("No records to process")
    except Exception as error:
        logger.exception(error)
    

    
    return {
        'statusCode': 200,
        'body': 'Processing complete'
    }
