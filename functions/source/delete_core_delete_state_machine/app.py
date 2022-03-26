import json
from botocore.vendored import requests
import boto3

client = boto3.client('networkmanager')

def lambda_handler(event, context):
    try:
        print(event['networkDetails']['Payload']['CoreNetworkId'])
        coreNetworkId = event['networkDetails']['Payload']['CoreNetworkId']
        response = client.delete_core_network(CoreNetworkId=coreNetworkId)
        print(response)
        if response['CoreNetwork']['State'] == 'DELETING':
            print('DELETING')
            return('DELETING')
        else:
            #to-dp: write error handling
            print('ERROR')
    except Exception as e:
        requests_data=json.dumps(dict(Status='FAILURE',Reason='Exception: %s' % e,UniqueId='DeleteStateMachine',Data='Delete Core Lambda')).encode('utf-8')
        response = requests.put(event['ResourceProperties']['WaitHandle'], data=requests_data, headers={'Content-Type':''})    
