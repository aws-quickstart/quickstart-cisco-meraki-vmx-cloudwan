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
        logger.info('Creating sdwan vpc attachment')
        response = client.create_vpc_attachment(
            CoreNetworkId=event['CoreNetworkId'],
            VpcArn=event['VpcArn'],
            SubnetArns=event['SubnetArns'],
            Tags=[
                {
                    'Key': 'name',
                    'Value': 'Meraki-SDWAN-VPC'
                },
            ],
        )
        VpcAttachmentId = response['VpcAttachment']['Attachment']['AttachmentId']
    except botocore.exceptions.ClientError as error:
        raise error

    except botocore.exceptions.ParamValidationError as error:
        raise ValueError('The parameters you provided are incorrect: {}'.format(error))
    return VpcAttachmentId