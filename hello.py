import json

def lambda_handler(event, context):
    # Print statements appear in CloudWatch logs
    print("Hello from Lambda!") 
    
    return {
        'statusCode': 200,
        'body': json.dumps('Hello World from Python!')
    }
