import boto3
import botocore
import logging
import uuid

client = boto3.client('networkmanager')

# Set up our logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

def lambda_handler(event,context):
    print('Event: {}'.format(event))

    try: 
        logger.info('Creatng a core network for Meraki cloudwan')
        id = uuid.uuid1()
        network_name = event['GlobalNetworkId'] + "-" + 'core-network'
        core_network = client.create_core_network(
            GlobalNetworkId = event['GlobalNetworkId'],
            Description='meraki core network',
            Tags=[
                {
                    'Key': 'Name',
                    'Value': network_name 
                },
            ]
        )
        core_network_id = core_network['CoreNetwork']['CoreNetworkId']
    except botocore.exceptions.ClientError as error:
        raise error

    except botocore.exceptions.ParamValidationError as error:
        raise ValueError('The parameters you provided are incorrect: {}'.format(error))
    return core_network_id