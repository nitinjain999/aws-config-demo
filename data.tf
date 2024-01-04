data "archive_file" "lambda_function" {
  type        = "zip"
  output_path = "/tmp/Lambda.zip"

  source {
    filename = "index.py"
    content  = <<-EOF
import boto3
import json
import logging

# Initialize logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    try:
        security_group_id = event['detail']['requestParameters']['groupId']
        logger.info(f"Processing Security Group: {security_group_id}")
    except KeyError as e:
        error_message = f"Failed to extract security group ID: {str(e)}"
        logger.error(error_message)
        return {
            'statusCode': 400,
            'body': json.dumps(error_message)
        }

    client = boto3.client('ec2')

    try:
        response = client.describe_security_group_rules(
            Filters=[{'Name': 'group-id', 'Values': [security_group_id]}]
        )

        for rule in response.get('SecurityGroupRules', []):
            ip_protocol = rule.get('IpProtocol', '')
            from_port = rule.get('FromPort', 0)
            to_port = rule.get('ToPort', 0)
            logger.info(f"Checking rule: Protocol {ip_protocol}, Ports {from_port}-{to_port}")

            if not rule.get('IsEgress', True) and ip_protocol == 'tcp' and from_port <= 22 <= to_port:
                ip_ranges = rule.get('CidrIpv4', [])
                ipv6_ranges = rule.get('CidrIpv6', [])
                if '0.0.0.0/0' in ip_ranges or '::/0' in ipv6_ranges:
                    logger.info(f"Found unrestricted access rule in Security Group: {security_group_id}")
                    try:
                        revoke_params = {
                            'GroupId': security_group_id,
                            'IpPermissions': [{
                                'IpProtocol': ip_protocol,
                                'FromPort': from_port,
                                'ToPort': to_port,
                                'IpRanges': [{'CidrIp': ip_range} for ip_range in ip_ranges if ip_range == '0.0.0.0/0'],
                                'Ipv6Ranges': [{'CidrIpv6': ip_range} for ip_range in ipv6_ranges if ip_range == '::/0']
                            }]
                        }
                        client.revoke_security_group_ingress(**revoke_params)
                        logger.info(f"Revoked unrestricted access on port 22 for Security Group: {security_group_id}")
                    except Exception as revoke_error:
                        logger.error(f"Failed to revoke rule for Security Group {security_group_id}: {str(revoke_error)}")

        logger.info(f"Successfully processed Security Group: {security_group_id}")

    except Exception as e:
        error_message = f"Error processing Security Group {security_group_id}: {str(e)}"
        logger.error(error_message)
        return {
            'statusCode': 500,
            'body': json.dumps(error_message)
        }

    return {
        'statusCode': 200,
        'body': json.dumps('Successfully executed')
    }

EOF
  }
}

