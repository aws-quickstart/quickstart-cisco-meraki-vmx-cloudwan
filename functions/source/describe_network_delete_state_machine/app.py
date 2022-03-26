import json
from botocore.vendored import requests
import boto3

client = boto3.client('networkmanager')


def lambda_handler(event, context):
    print('Event: {}'.format(event))
    network={}
    try:
        #get GlobalNetworkID based upon predefined tag
        response = client.describe_global_networks()
        for gn in response['GlobalNetworks']:
            for tag in gn['Tags']:
                if tag['Key'] == 'quickstart-control-DO-NOT-MODIFY' and tag['Value'] == 'Meraki CloudWAN Quick Start':
                    print('Global NetworkID: ' + gn['GlobalNetworkId'])
                    print('tag: '+ tag['Key'], tag['Value'])
                    network['GlobalNetworkId'] = gn['GlobalNetworkId']
        
        
        #get the proper core network associated with the GlobalNetworkID
        response = client.list_core_networks()
        for core in response['CoreNetworks']:
            #is try/except the proper way to do this?
            #not all items returned will have a global network, so it will throw an error without try/except
            try: 
                if core['GlobalNetworkId'] == network['GlobalNetworkId']:
                    #print(core['CoreNetworkId'])
                    network['CoreNetworkId'] = core['CoreNetworkId']
            except:
                #print('global network not found')
                pass
        
        network['Attachments'] = [] #create list to include multiple attachments
        response = client.list_attachments(CoreNetworkId=network['CoreNetworkId'])
        for attachment in response['Attachments']:
            #print(attachment)
            try: 
                if attachment['SegmentName'] == 'sdwan':
                    #print(attachment['AttachmentId'])
                    network['Attachments'].append(attachment['AttachmentId'])
            except:
                #print('SegmentName not found')
                pass                
        
        
        #add error logic if network not found
        print(network)
        return(network)
        
    except Exception as e:
        requests_data=json.dumps(dict(Status='FAILURE',Reason='Exception: %s' % e,UniqueId='DeleteStateMachine',Data='Describe Network Lambda')).encode('utf-8')
        response = requests.put(event['ResourceProperties']['WaitHandle'], data=requests_data, headers={'Content-Type':''})      
