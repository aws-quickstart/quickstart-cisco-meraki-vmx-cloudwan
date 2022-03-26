import json
from botocore.vendored import requests
import boto3

client = boto3.client('networkmanager')

def lambda_handler(event, context):

    try:
        globalNetworkId = event['networkDetails']['Payload']['GlobalNetworkId']
        response = client.delete_global_network(GlobalNetworkId=globalNetworkId)
        print(response)

    except Exception as e:
        requests_data=json.dumps(dict(Status='FAILURE',Reason='Exception: %s' % e,UniqueId='DeleteStateMachine',Data='Delete Global Lambda')).encode('utf-8')
        response = requests.put(event['ResourceProperties']['WaitHandle'], data=requests_data, headers={'Content-Type':''})            