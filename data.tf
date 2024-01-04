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
    # Log the received event for inspection
    logger.info(f"Received event: {json.dumps(event)}")

    try:
        # Update this part to extract the security group ID based on your event structure
        security_group_id = None
        if 'detail' in event:
            security_group_id = event['detail'].get('requestParameters', {}).get('groupId')
        elif 'Payload' in event:
            payload = json.loads(event['Payload']) if isinstance(event['Payload'], str) else event['Payload']
            security_group_id = payload.get('groupId')
        
        if not security_group_id:
            raise KeyError("Security group ID key not found in the event")

        logger.info(f"Processing Security Group: {security_group_id}")

        # Initialize EC2 client
        ec2_client = boto3.client('ec2')

        # Describe security group rules
        response = ec2_client.describe_security_group_rules(
            Filters=[{'Name': 'group-id', 'Values': [security_group_id]}]
        )

        for rule in response.get('SecurityGroupRules', []):
            # Check for ingress rules allowing unrestricted access
            if rule.get('IsEgress', False) == False and rule.get('IpProtocol', '') == 'tcp' and \
               rule.get('FromPort', 0) <= 22 <= rule.get('ToPort', 0) and \
               ('0.0.0.0/0' in rule.get('CidrIpv4', []) or '::/0' in rule.get('CidrIpv6', [])):
                logger.info(f"Revoking unrestricted SSH access in Security Group: {security_group_id}")

                # Construct the IpPermission structure
                ip_permission = {
                    'IpProtocol': rule['IpProtocol'],
                    'FromPort': rule['FromPort'],
                    'ToPort': rule['ToPort'],
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}] if '0.0.0.0/0' in rule.get('CidrIpv4', []) else [],
                    'Ipv6Ranges': [{'CidrIpv6': '::/0'}] if '::/0' in rule.get('CidrIpv6', []) else []
                }

                # Revoke the ingress rule
                ec2_client.revoke_security_group_ingress(
                    GroupId=security_group_id,
                    IpPermissions=[ip_permission]
                )
                logger.info(f"Revoked SSH access for CIDRs in Security Group: {security_group_id}")

        return {
            'statusCode': 200,
            'body': json.dumps(f"Successfully processed Security Group: {security_group_id}")
        }

    except KeyError as e:
        error_message = f"Failed to extract security group ID: {str(e)}"
        logger.error(error_message)
        return {
            'statusCode': 400,
            'body': json.dumps(error_message)
        }
    except Exception as e:
        error_message = f"Error processing Security Group {security_group_id}: {str(e)}"
        logger.error(error_message)
        return {
            'statusCode': 500,
            'body': json.dumps(error_message)
        }

EOF
  }
}

