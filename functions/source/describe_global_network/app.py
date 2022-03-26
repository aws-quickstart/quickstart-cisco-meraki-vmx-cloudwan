import boto3

client = boto3.client('networkmanager')

def lambda_handler(event,context):
    print('Event: {}'.format(event))

    response = client.describe_global_networks(
        GlobalNetworkIds=[event['GlobalNetworkId']]
    )

    return response['GlobalNetworks'][0]['State']