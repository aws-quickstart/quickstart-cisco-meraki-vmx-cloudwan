import json
from logging import exception
from botocore.vendored import requests
import boto3

client = boto3.client('networkmanager')

def lambda_handler(event, context):
    #print(event)
    try:
        print(event['networkDetails']['Payload'])
        attachments = event['networkDetails']['Payload']['Attachments']
        #delete attachments
        #if deleting state, pass , else fail
        for attachment in attachments:
            #print(attachment)
            response = client.delete_attachment(AttachmentId=attachment)
            print(response)
            if response['Attachment']['State'] == 'DELETING':
                print('DELETING',attachment)
            else:
                #to-do: error handling
                print('ERROR',attachment)
                return('ERROR')
        return('DELETING')
    except Exception as e:
        requests_data=json.dumps(dict(Status='FAILURE',Reason='Exception: %s' % e,UniqueId='DeleteStateMachine',Data='Delete Attachment Lambda')).encode('utf-8')
        response = requests.put(event['ResourceProperties']['WaitHandle'], data=requests_data, headers={'Content-Type':''})        

    