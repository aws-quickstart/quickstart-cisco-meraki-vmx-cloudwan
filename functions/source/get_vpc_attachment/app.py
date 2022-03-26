import boto3

client = boto3.client('networkmanager')

def lambda_handler(event,context):
    print('Event: {}'.format(event))

    response = client.get_vpc_attachment(
        AttachmentId=event['Destinations'],
    )

    return response['VpcAttachment']['Attachment']['State']