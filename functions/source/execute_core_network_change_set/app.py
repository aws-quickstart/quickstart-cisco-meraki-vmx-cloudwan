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
        logger.info('executing network policy version ' + str(event['NetworkPolicyVersionId']))
        response = client.execute_core_network_change_set(
            CoreNetworkId = event['CoreNetworkId'],
            PolicyVersionId = event['NetworkPolicyVersionId']
        )
    except botocore.exceptions.ClientError as error:
        raise error

    except botocore.exceptions.ParamValidationError as error:
        raise ValueError('The parameters you provided are incorrect: {}'.format(error))
    return response