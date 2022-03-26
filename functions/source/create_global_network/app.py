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
        logger.info('Creatng a global network for Meraki cloudwan')
        id = uuid.uuid1()
        network_name = event['network_name'] + "-" + str(id)[:8]
        #network_name = default_network_name + "-" + str(id)[:8]
        global_network = client.create_global_network(
            Description='meraki global network',
            Tags=[
                {
                    'Key': 'Name',
                    'Value': network_name 
                }
            ]
        )
        global_network_id = global_network['GlobalNetwork']['GlobalNetworkId']
    except botocore.exceptions.ClientError as error:
        raise error

    except botocore.exceptions.ParamValidationError as error:
        raise ValueError('The parameters you provided are incorrect: {}'.format(error))
    return global_network_id
    