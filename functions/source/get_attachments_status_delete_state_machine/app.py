import json
from botocore.vendored import requests
import boto3

client = boto3.client('networkmanager')

def lambda_handler(event, context):
    try:
        print(event)
        print(event['networkDetails']['Payload']['CoreNetworkId'])
        coreNetworkId = event['networkDetails']['Payload']['CoreNetworkId']
        response = client.list_attachments(CoreNetworkId=coreNetworkId)
        print(response)
        for attachment in response['Attachments']:
            print(attachment)

        if response['Attachments']:
            print('WAITING')
            return('WAITING')
        else:
            print('DELETED')
            return('DELETED')
    except Exception as e:
        requests_data=json.dumps(dict(Status='FAILURE',Reason='Exception: %s' % e,UniqueId='DeleteStateMachine',Data='Get Attachment Status Lambda')).encode('utf-8')
        response = requests.put(event['ResourceProperties']['WaitHandle'], data=requests_data, headers={'Content-Type':''})   