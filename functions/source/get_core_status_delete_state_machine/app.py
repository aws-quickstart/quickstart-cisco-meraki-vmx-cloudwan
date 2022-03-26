import json
from botocore.vendored import requests
import boto3

client = boto3.client('networkmanager')

def lambda_handler(event, context):
    try:
        coreNetworkId = event['networkDetails']['Payload']['CoreNetworkId']
        response = client.list_core_networks()
        for core in response['CoreNetworks']:
            if core['CoreNetworkId'] == coreNetworkId:
                print('WAITING')
                return('WAITING')
        print('DELETED')
        return('DELETED')
    except Exception as e:
        requests_data=json.dumps(dict(Status='FAILURE',Reason='Exception: %s' % e,UniqueId='DeleteStateMachine',Data='Get Core Status Lambda')).encode('utf-8')
        response = requests.put(event['ResourceProperties']['WaitHandle'], data=requests_data, headers={'Content-Type':''})   

# Can't use describe_global_network because it returns no core network info
# shouldn't use get_core_network because if the cn is deleted, it just throws an error, looks ugly
# might have to use list_core_networks, and search the output for the known existing coreNetworkId
