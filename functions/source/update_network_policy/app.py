import boto3
import botocore
import logging
import json

client = boto3.client('networkmanager')

# Set up our logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

def generate_network_policy(event):
    try: 
        #fetch latest existing network policy document
        response = client.list_core_network_policy_versions(CoreNetworkId = event['CoreNetworkId'])
        if response['CoreNetworkPolicyVersions'] != []:
            policy_response = client.get_core_network_policy(CoreNetworkId = event['CoreNetworkId'], Alias = 'LATEST')
            policy = json.loads(policy_response['CoreNetworkPolicy']['PolicyDocument'])
        #create a new default policy skeleton
        else:
            policy = {}
            policy['version'] = "2021.12"
            policy['core-network-configuration'] = {
                'asn-ranges': []
            }
            policy['core-network-configuration'] = {
                'edge-locations': []
            }
            policy['segments'] = [
                {
                    'name': 'sdwan',
                    'require-attachment-acceptance': False
                }
            ]
            policy['segment-actions'] = [
                {
                    'action': "create-route",
                    'segment': 'sdwan',
                    'destination-cidr-blocks': [],
                    'destinations': ['blackhole'],
                    'description': 'create route for branch traffic to go out via SD-WAN VPC Attachment'
                },
                {
                    'action': 'share',
                    'mode': 'attachment-route',
                    'segment': 'sdwan',
                    'share-with': '*'
                }
            ]
            policy['attachment-policies'] = [
                {
                    'rule-number': 100,
                    'conditions': [
                        {
                            'type': 'tag-value',
                            'key': 'name',
                            'operator': 'contains',
                            'value': 'Meraki-SDWAN-VPC'
                        }
                    ],
                    'action': {
                        'association-method': 'constant',
                        'segment': 'sdwan'
                    }
                }
            ]

        #add the policy changes
        if 'asn-range' in event.keys():
            if event['asn-range']: 
                policy['core-network-configuration']['asn-ranges'] = event['asn-range']

        if 'region' in event.keys():
            region_list = policy['core-network-configuration']['edge-locations']
            region_list.append({'location': region}) 
            policy['core-network-configuration']['edge-locations'] = region_list

        # Q: How does one get region awareness for new branches discovered
        # as an enhancement, may want to implement the case to create a new route when one doesn't exist on an existing policy
        if 'destination_cidr_blocks' in event.keys():
            # append to destination-cidr-blocks in create-route action only for 'sdwan' segment
            for action in policy['segment-actions']:
                # does create-route action exist?
                if action['action'] == 'create-route':
                    # append cidr if 'sdwan segment exists
                    if action['segment'] == 'sdwan':
                        for cidr in event['destination_cidr_blocks']:
                            action['destination-cidr-blocks'].append(cidr)

        if 'Destinations' in event.keys():
            # if create-route segment-action exists, append destination if no 'blackhole' exists otherwise replace 'blackhole'
            for action in policy['segment-actions']:
                if action['action'] == 'create-route':
                    # append destinaciont only to 'sdwan' segment exists
                    if action['segment'] == 'sdwan':
                        if action['destinations'] == ['blackhole']:
                            action['destinations'] = [event['Destinations']]
                        else:
                            for destination in event['Destinations']:
                                action['destinations'].append(destination)

        # as an enhancement, may want to implement the case to create a new attachment policy when one doesn't exist on an existing policy
        
    except botocore.exceptions.ClientError as error:
        raise error

    except botocore.exceptions.ParamValidationError as error:
        raise ValueError('The parameters you provided are incorrect: {}'.format(error))
    
    return policy
def lambda_handler(event,context):
    print('Event: {}'.format(event))

    try: 
        logger.info('Attaching network policy document to Meraki cloudwan core network')
        network_policy = generate_network_policy(event)
        print(network_policy)
        print(json.dumps(network_policy))
        response = client.put_core_network_policy(
            CoreNetworkId=event['CoreNetworkId'],
            PolicyDocument= json.dumps(network_policy)
        )

        network_policy_version_id = response['CoreNetworkPolicy']['PolicyVersionId']
    except botocore.exceptions.ClientError as error:
        raise error

    except botocore.exceptions.ParamValidationError as error:
        raise ValueError('The parameters you provided are incorrect: {}'.format(error))
    return network_policy_version_id