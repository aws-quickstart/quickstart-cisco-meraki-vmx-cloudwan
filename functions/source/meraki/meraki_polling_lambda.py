import os
import requests
import meraki
import boto3
import botocore
import logging
import json
import sys
import threading
import cfnresponse


from botocore.exceptions import ClientError

logging.basicConfig(stream = sys.stdout)
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def get_meraki_key():
    secret_name = 'MerakiAPIKey' # nosec
    region = os.environ['AWS_REGION']
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region,
    )
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            logger.info('The requested secret ' + secret_name + ' was not found')
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            logger.info('The request was invalid due to {}:'.format(e))
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            logger.info('The request had invalid params: {}'.format(e))
    else:
        # Secrets Manager decrypts the secret value using the associated KMS CMK
        # Depending on whether the secret was a string or binary, only one of these fields will be populated
        if 'SecretString' in get_secret_value_response:
            text_secret_data = json.loads(get_secret_value_response['SecretString'])
            merakiapikey = text_secret_data['merakiapikey']
            return merakiapikey
        else:
            binary_secret_data = get_secret_value_response['SecretBinary']
            return binary_secret_data
    
def get_all_vpn_routes(dashboard, org_id, vmx1_id, vmx2_id):
    org_vpn_status = dashboard.appliance.getOrganizationApplianceVpnStatuses(
    org_id, total_pages='all'
    )
    vpn_routes_vmx1 = []
    vpn_routes_vmx2 = []
    for networks in org_vpn_status:
        if networks['vpnMode'] == 'spoke': 
            for peers in networks['merakiVpnPeers']:
                if peers['networkId'] == vmx1_id or peers['networkId'] == vmx2_id:
                    vpn_status = dashboard.appliance.getNetworkApplianceVpnSiteToSiteVpn(networks['networkId'])
                    for i in vpn_status['hubs']:
                        if i['hubId'] == vmx1_id:
                            for subnets in networks['exportedSubnets']:
                                logger.info('Meraki Dashboard: Found routes for vMX1 hub')
                                vpn_routes_vmx1.append(subnets.get('subnet'))
                                logger.info(vpn_routes_vmx1)
                            break
                        elif i['hubId'] == vmx2_id:
                            for subnets in networks['exportedSubnets']:
                                logger.info('Meraki Dashboard: Found routes for vMX2 hub')
                                vpn_routes_vmx2.append(subnets.get('subnet'))
                                logger.info(vpn_routes_vmx2)
                            break
                else:
                    logger.info('Meraki Dashboard: No routes found for vMX Hubs')
                    pass 
    return vpn_routes_vmx1, vpn_routes_vmx2

def get_meraki_tagged_networks(dashboard, org_id, vmx_tag):
    # executing API call to obtain all Meraki networks in the organization
    organization_networks_response = dashboard.organizations.getOrganizationNetworks(
        org_id, total_pages='all'
    )
    vmx_network = [x for x in organization_networks_response if str(vmx_tag) in str(x['tags'])[1:-1]]

    return vmx_network[0]['id']

def check_vmx_status(dashboard, org_id, vmx_id, ec2_vmx_id):
    region = os.environ['AWS_REGION']
    ec2 = boto3.client('ec2', region_name=region) 
    org_device_status = dashboard.organizations.getOrganizationDevicesStatuses(
        org_id, total_pages='all'
    )
    logger.info('Checking vMX status for meraki org id {0} and ec2 instance id {1}'.format(vmx_id, ec2_vmx_id))
    meraki_vmx_status = [x for x in org_device_status if str(vmx_id) in str(x['networkId'])][0]['status']
    ec2_vmx_status = ec2.describe_instance_status(InstanceIds=[ec2_vmx_id], IncludeAllInstances=True)
    if meraki_vmx_status == 'online' and ec2_vmx_status['InstanceStatuses'][0]['InstanceState']['Name'] == 'running':
        vmx_status = 'online'
    else:
        vmx_status ='offline'

    return vmx_status
            
def update_tgw_rt(vpn_routes, tgw_rt_id, tgw_attach_id):
    region = os.environ['AWS_REGION']
    ec2 = boto3.client('ec2', region_name=region)
    uniq_vpn_routes = list(set(vpn_routes))
    logger.info("EC2 TGW Route Update {0}".format(uniq_vpn_routes))
    #Checking if the route already exsists, if so skip updating the TGW route table
    for route in uniq_vpn_routes:
        exsisting_route = ec2.search_transit_gateway_routes(
            TransitGatewayRouteTableId= tgw_rt_id,
            Filters=[
                { 'Name': 'route-search.exact-match',
                  'Values': [route]

            }]
        )
        if bool(exsisting_route['Routes']):
            logger.info("Transit Gateway RT: No update, route {0} exsists, skipping update".format(route))
            pass
        else:
            logger.info("Transit Gateway RT: New route, adding route {0}".format(route))
            ec2.create_transit_gateway_route(
            DestinationCidrBlock= route,
            TransitGatewayRouteTableId=tgw_rt_id,
            TransitGatewayAttachmentId=tgw_attach_id
           )

def update_vpc_rt(vpn_routes, vmx_id, rt_id):
    region = os.environ['AWS_REGION']
    ec2 = boto3.client('ec2', region_name=region)
    uniq_vpn_routes = list(set(vpn_routes))
    #Checking exsisting routes in the VPC table
    raw_exsisting_vpc_rts = ec2.describe_route_tables(Filters = [{"Name": "route-table-id", "Values": [rt_id]}])['RouteTables'][0]['Routes']
    exsisting_routes = []
    for routes in raw_exsisting_vpc_rts:
        if 'InstanceId' in routes and routes['InstanceId'] == vmx_id:
            exsisting_routes.append(routes['DestinationCidrBlock'])
        else:
            logger.info('VPC RT: No matching routes found')
    #Compare exsisting routes with new routes
    update_routes = [x for x in exsisting_routes + uniq_vpn_routes if x not in exsisting_routes]
    if update_routes:
        logger.info('VPC RT: New routes for update {0}'.format(update_routes))
        for routes in update_routes:
            try:
                ec2.create_route(
                DestinationCidrBlock=routes,
                InstanceId=vmx_id,
                RouteTableId=rt_id
              )
            except botocore.exceptions.ClientError as error:
                if error.response['Error']['Code'] == 'RouteAlreadyExists':
                    ec2.replace_route(
                    DestinationCidrBlock=routes,
                    InstanceId=vmx_id,
                    RouteTableId=rt_id
                )
                else:
                    logger.info('VPC RT: Boto exception, adding routes to vpc table failed due to {0}'.format(error.response['Error']['Code'])) 
    else:
        logger.info('VPC RT: No new routes for update') 

def get_ec2_instance_id(instance_tag):
    region = os.environ['AWS_REGION']
    ec2 = boto3.client('ec2', region_name=region)
    filters = [{"Name":"tag:MerakiTag", "Values":[instance_tag]}]
    instances = ec2.describe_instances(Filters=filters)
    instance_id = []
    logger.info('AWS EC2: Checking for vMX instances with instance tag {0}'.format(instance_tag))
    for i in instances['Reservations']:
        instance_id.append(i['Instances'][0]['InstanceId'])
        if i['Instances'][0]['State']['Name'] == 'running':
            logger.info('AWS EC2: Running vMX instance found with tag {0} and instance id {1}'.format(instance_tag, instance_id))
        else:
            logger.info('AWS EC2: Shutdown/Terminated vMX instance found with instance tag {0} and instance id {1}'.format(instance_tag, i['Instances'][0]['InstanceId']))
    if len(instance_id) > 1:
        logger.error('AWS EC2: More that one running instance with the same tag, please remove tag from stale/broken instance')
        logger.error('AWS EC2: The following instances {0}, were found with the tag {1}'.format(instance_id, instance_tag))
        exit
    else:
        return instance_id[0]

def update_network_event_json(vpn_routes, vpc_arn, subnet_arns, global_network_name, event_bus_name, base_region_name):
    network_name = global_network_name
    region = os.environ['AWS_REGION']
    aws_events_client = boto3.client('events', region_name=base_region_name)
    aws_nm_client = boto3.client('networkmanager')
    network = {}
    cw_static_routes = []
    vpn_routes_flat_list = [routes for sublist in vpn_routes for routes in sublist]
    print("vpn_routes_flat_list before dedup: ")
    print(vpn_routes_flat_list) 
    vpn_routes_flat_list = list(dict.fromkeys(vpn_routes_flat_list))
    print("vpn_routes_flat_list: ")
    print(vpn_routes_flat_list)
    #str_vpn_routes = ",".join(set(vpn_routes_flat_list))
    try: 
        response = aws_nm_client.describe_global_networks()
        for gn in response['GlobalNetworks']:
            for tag in gn['Tags']:
                if tag['Key'] == 'Name' and tag['Value'] == network_name:
                    print('Global NetworkID: ' + gn['GlobalNetworkId'])
                    print('tag: '+ tag['Key'], tag['Value'])
                    network['GlobalNetworkId'] = gn['GlobalNetworkId']
        
        
        #get the proper core network associated with the GlobalNetworkID
        response = aws_nm_client.list_core_networks()
        for core in response['CoreNetworks']:
            #is try/except the proper way to do this?
            #not all items returned will have a global network, so it will throw an error without try/except
            try: 
                if core['GlobalNetworkId'] == network['GlobalNetworkId']:
                    network['CoreNetworkId'] = core['CoreNetworkId']
            except:
                logger.info('Global Network not found')
                pass
        print(network['CoreNetworkId'])
        attachments = aws_nm_client.list_attachments(AttachmentType='VPC', EdgeLocation=region, CoreNetworkId=network['CoreNetworkId'])
        print('attachments:')
        print(str(attachments))

        #loop through json of all attachments for single region.  There should only be 1 Transit VPC attachment per region (tag of Name/Meraki-SDWAN-VPC )
        #once found, define vpc_attachment_id (also core_network_id but technically we could use network['CoreNetworkId'] instead )
        for k,v in attachments.items():
            if k == 'Attachments':
                for i in v:
                    print(i)
                    if i['Tags'][0]['Key'] == 'Name':
                        if i['Tags'][0]['Value'] == 'Meraki-SDWAN-VPC':
                            vpc_attachment_id = i['AttachmentId']
                            core_network_id = i['CoreNetworkId']
                            print("core_network_id:")
                            print(core_network_id)
                            print("vpc_attachment_id:")
                            print(vpc_attachment_id)  
        #Get routes from cloudwan
        cw_routes = aws_nm_client.get_network_routes(GlobalNetworkId=network['GlobalNetworkId'], RouteTableIdentifier={'CoreNetworkSegmentEdge': {'CoreNetworkId': core_network_id, 'SegmentName': 'sdwan', 'EdgeLocation': region}})
        print('cw_routes')
        print(str(cw_routes))
        for routes in cw_routes['NetworkRoutes']:
            if routes['Type'] == 'STATIC':
                cw_static_routes.append(routes['DestinationCidrBlock'])
            else:
                logger.info('No static routes in cloudwan core network')
        print('cw_static_routes: ')
        print(cw_static_routes)
        if vpn_routes_flat_list != cw_static_routes:
        # new routes or delete old routes
            logger.info("Change in routes detected.  Sending routes to the Update State Machine in Base Region")
            response = aws_events_client.put_events(
                Entries=[
                {
                    'Source': 'com.aws.merakicloudwanquickstart',
                    'DetailType': 'update global network requested',
                    'Detail': json.dumps({"network_name": network_name, "regions": [region], "destination_cidr_blocks": vpn_routes_flat_list, "VpcAttachmentId": [vpc_attachment_id], "CoreNetworkId": core_network_id}),
                    'EventBusName': event_bus_name
                }
                ]
            )
            logger.info(response)
            return response
        else:
            logger.info('No new routes, skipping the update state machine')
    except Exception as e:
                print(e)
                #requests_data=json.dumps(dict(Status='FAILURE',Reason='Exception: %s' % e,UniqueId='DeleteStateMachine',Data=event['ResourceProperties'])).encode('utf-8')
                #response = requests.put(event['ResourceProperties']['WaitHandle'], data=requests_data, headers={'Content-Type':''})
                #print (response)

def update_rt(org_id, vmx1_tag, vmx2_tag, vpc_arn, az1_subnet_arn, az2_subnet_arn, rt_id, global_network_name, event_bus_name, base_region_name):
    org_id = org_id
    vmx1_tag = vmx1_tag
    vmx2_tag = vmx2_tag
    subnet_arns = [az1_subnet_arn, az2_subnet_arn]
    meraki_api_key = get_meraki_key()
    logger.info('Meraki API Key')
    logger.info(meraki_api_key)
    meraki_dashboard = meraki.DashboardAPI(meraki_api_key, suppress_logging=True)
    logger.info(meraki_dashboard)
    #get vmx ec2 instance ids using tags
    ec2_vmx1_id = get_ec2_instance_id(vmx1_tag)
    ec2_vmx2_id = get_ec2_instance_id(vmx2_tag)
    #get corresponding vmx network ids using tags
    meraki_vmx1_id = get_meraki_tagged_networks(meraki_dashboard, org_id, vmx1_tag)
    meraki_vmx2_id = get_meraki_tagged_networks(meraki_dashboard, org_id, vmx2_tag)
    #get autovpn branch site routes for the vMXs 
    vpn_routes = get_all_vpn_routes(meraki_dashboard, org_id, meraki_vmx1_id, meraki_vmx2_id)
    ##check vmx status
    if ec2_vmx1_id and ec2_vmx1_id and meraki_vmx1_id and meraki_vmx1_id:
        vmx1_status = check_vmx_status(meraki_dashboard, org_id, meraki_vmx1_id, ec2_vmx1_id)
        vmx2_status = check_vmx_status(meraki_dashboard, org_id, meraki_vmx2_id, ec2_vmx2_id)
    else:
        logger.error('vMX Instance Ids: No vMXs instance IDs found')
        exit()
    #update VPC route tables based on vMX instance state
    if vmx1_status == 'online' and vmx2_status == 'online':
        logger.info('vMX Status: vmx1 and vmx2 are both online')
        logger.info('VPC RT Update: Updating VPC route table for vMX1')
        update_vpc_rt(vpn_routes[0], ec2_vmx1_id, rt_id)
        logger.info('VPC RT Update: Updating VPC route table for vMX2')
        update_vpc_rt(vpn_routes[1], ec2_vmx2_id, rt_id)
    elif vmx1_status == 'online' and vmx2_status == 'offline':
        logger.info ("vMX Status: vmx1 online and vmx2 offline, moving all routes to vmx1")
        logger.info('VPC RT Update: Updating VPC route table for vMX1')
        update_vpc_rt(vpn_routes[0], ec2_vmx1_id, rt_id)
        update_vpc_rt(vpn_routes[1], ec2_vmx1_id, rt_id)
    elif vmx1_status == 'offline' and vmx2_status == 'online':
        logger.info ("vMX Status: vmx2 online and vmx1 offline, moving all routes to vmx2")
        logger.info('VPC RT Update: Updating VPC route table for vMX2')
        update_vpc_rt(vpn_routes[0], ec2_vmx2_id, rt_id)
        update_vpc_rt(vpn_routes[1], ec2_vmx2_id, rt_id)
    else:
        logger.info ('vMX1 and vMX2 are BOTH offline')
        #TODO: Cloudwatch enhancement to generate alerts when both vMXs are offline
    logger.info('Running Update Network Event') 
    update_network_event_json(vpn_routes, vpc_arn, subnet_arns, global_network_name, event_bus_name, base_region_name)
def timeout(event, context):
    logging.error('Execution is about to time out, sending failure response to CloudFormation')
    cfnresponse.send(event, context, cfnresponse.FAILED, {}, None)

def main(event, context):
    # This lambda function monitors the state of the vMX instances and updates the SDWAN VPC and TGW route tables accordingly.
    # The function gets instatiated on a periodic Cloudwatch event, the frequency of the periodic check is configurable and taken as an input for the cft templates. 

    try:
        logger.info('Lambda Execution: Executed on event {0}'.format(event))
        org_id = os.environ['meraki_org_id']
        rt_id = os.environ['rt_id']
        vmx1_tag = os.environ['vmx1_tag']
        vmx2_tag = os.environ['vmx2_tag']
        vpc_id = os.environ['vpc_id']
        vpc_arn = os.environ['vpc_arn']
        az1_subnet_arn = os.environ['az1_subnet_arn']
        az2_subnet_arn = os.environ['az2_subnet_arn']
        global_network_name = os.environ['global_network_name']
        event_bus_name = os.environ['event_bus_name']
        base_region_name = os.environ['base_region_name']
        update_rt(org_id, vmx1_tag, vmx2_tag, vpc_arn, az1_subnet_arn, az2_subnet_arn, rt_id, global_network_name, event_bus_name, base_region_name)

    except Exception as e:
        logging.error('Exception: %s' % e, exc_info=True)
        status = cfnresponse.FAILED
    
if __name__ == "__main__":   
    main('', '')