import boto3

client = boto3.client('networkmanager')

def lambda_handler(event,context):
    print('Event: {}'.format(event))

    response = client.get_core_network(
        CoreNetworkId=event['CoreNetworkId']
    )

    return response['CoreNetwork']['State']