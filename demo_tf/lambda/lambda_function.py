from __future__ import print_function
import boto3
import json
import os

ec2 = boto3.client('ec2')
ec2R = boto3.resource('ec2')
sns = boto3.client('sns')
sts = boto3.client('sts')
accountID = sts.get_caller_identity()["Account"]

customPorts = [22]
AllPort = '-1'
worldCidr = "0.0.0.0/0"
worldCidr6 = "::/0" 
snsTopicName = os.environ['snsTopicName']
snsTopicRegion = os.environ['region']
snsSubject = "AWS Security Group Alarm"
snsMessage = []
kube = range(30000, 40001)
for i in kube:
    customPorts.append(i)
flex_kube = range(15000, 16000)
for i in flex_kube:
    customPorts.append(i)

def normalize_paramter_names(ip_items):
    # Start building the permissions items list.
    new_ip_items = []

    # First, build the basic parameter list.
    for ip_item in ip_items:

        new_ip_item = {
            "IpProtocol": ip_item['ipProtocol'],
            "FromPort": ip_item['fromPort'],
            "ToPort": ip_item['toPort']
        }

        # CidrIp or CidrIpv6 (IPv4 or IPv6)?
        if 'ipv6Ranges' in ip_item and ip_item['ipv6Ranges']:
            # This is an IPv6 permission range, so change the key names.
            ipv_range_list_name = 'ipv6Ranges'
            ipv_address_value = 'cidrIpv6'
            ipv_range_list_name_capitalized = 'Ipv6Ranges'
            ipv_address_value_capitalized = 'CidrIpv6'
        else:
            ipv_range_list_name = 'ipRanges'
            ipv_address_value = 'cidrIp'
            ipv_range_list_name_capitalized = 'IpRanges'
            ipv_address_value_capitalized = 'CidrIp'

        ip_ranges = []

        # Next, build the IP permission list.
        for item in ip_item[ipv_range_list_name]['items']:
            ip_ranges.append(
                {ipv_address_value_capitalized: item[ipv_address_value]}
            )

        new_ip_item[ipv_range_list_name_capitalized] = ip_ranges

        new_ip_items.append(new_ip_item)

    return new_ip_items

def lambda_handler(event, context):
    print(event)
    for item in event['detail']['requestParameters']['ipPermissions']['items']:
        if 'items' in item['ipRanges']:
            for ipCidr in item['ipRanges']['items']:
                for targetPort in customPorts:
                    try:
                        if (item['toPort'] == targetPort and item['fromPort'] == targetPort) and ipCidr['cidrIp'] == worldCidr:
                            PublishMessage = {'Region': event['detail']['awsRegion'], 'Security GroupId': event['detail']['requestParameters']['groupId'], 'IngressRull': json.dumps(event['detail']['requestParameters']['ipPermissions']['items'])}
                            snsMessage.append(PublishMessage)
                            ec2.revoke_security_group_ingress(CidrIp=worldCidr, FromPort=targetPort, ToPort=targetPort, GroupId=event['detail']['requestParameters']['groupId'], IpProtocol=item['ipProtocol'])
                            print(PublishMessage)
                        else:
                            pass
                    except KeyError:
                        if item['ipProtocol'] == AllPort and ipCidr['cidrIp'] == worldCidr:
                            PublishMessage = {'Region': event['detail']['awsRegion'], 'Security GroupId': event['detail']['requestParameters']['groupId'], 'IngressRull': json.dumps(event['detail']['requestParameters']['ipPermissions']['items'])}
                            snsMessage.append(PublishMessage)
                            ec2.revoke_security_group_ingress(CidrIp=worldCidr, GroupId=event['detail']['requestParameters']['groupId'], IpProtocol=item['ipProtocol'])
                            print(PublishMessage)

        elif 'items' in item['ipv6Ranges']:
            for ipCidr in item['ipv6Ranges']['items']:
                for targetPort in customPorts:
                    try:
                        if (item['toPort'] == targetPort and item['fromPort'] == targetPort) and ipCidr['cidrIpv6'] == worldCidr6:
                            PublishMessage = {'Region': event['detail']['awsRegion'], 'Security GroupId': event['detail']['requestParameters']['groupId'], 'IngressRull': json.dumps(event['detail']['requestParameters']['ipPermissions']['items'])}
                            snsMessage.append(PublishMessage)
                            ip_permissions = normalize_paramter_names(event['detail']['requestParameters']['ipPermissions']['items'])
                            print(ip_permissions)
                            ec2.revoke_security_group_ingress(GroupId=event['detail']['requestParameters']['groupId'], IpPermissions=ip_permissions)
                            print(PublishMessage)
                        else:
                            pass
                    except KeyError:
                        if item['ipProtocol'] == AllPort and ipCidr['cidrIpv6'] == worldCidr6:
                            PublishMessage = {'Region': event['detail']['awsRegion'], 'Security GroupId': event['detail']['requestParameters']['groupId'], 'IngressRull': json.dumps(event['detail']['requestParameters']['ipPermissions']['items'])}
                            snsMessage.append(PublishMessage)
                            ip_permissions = normalize_paramter_names(event['detail']['requestParameters']['ipPermissions']['items'])
                            ec2.revoke_security_group_ingress(GroupId=event['detail']['requestParameters']['groupId'], IpPermissions=ip_permissions)
                            print(PublishMessage)
        else:
            pass
    if not snsMessage:
        print("No sgRule Violation")
    else:
        notifyMessage = "SG_AUTO_REMEDIATION: The following API call: {0} was made by: {1} on SecurityGroupId: {2} with these IpPermissions: {3}".format(event['detail']['eventName'], event['detail']['userIdentity']['arn'], event['detail']['requestParameters']['groupId'], json.dumps(event['detail']['requestParameters']['ipPermissions']))
        snsTopicArn = "arn:aws:sns:{0}:{1}:{2}".format(snsTopicRegion, accountID, snsTopicName)
        sent = sns.publish(TopicArn=snsTopicArn, Message=str(notifyMessage), Subject=snsSubject)
        print("MessageId: " + sent['MessageId'] + "\nPublished Successfully!!!")
        print(notifyMessage)
