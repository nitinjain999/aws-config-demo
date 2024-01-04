data "archive_file" "lambda_function" {
  type        = "zip"
  output_path = "/tmp/Lambda.zip"

  source {
    filename = "index.py"
    content  = <<-EOF
import boto3
import json

def lambda_handler(event, context):
    # Extract the security group ID from the event
    security_group_id = event['detail']['requestParameters']['groupId']
    client = boto3.client('ec2')

    try:
        # Describe the security group rules
        response = client.describe_security_group_rules(
            Filters=[
                {'Name': 'group-id', 'Values': [security_group_id]},
                {'Name': 'ip-protocol', 'Values': ['tcp']},
                {'Name': 'from-port', 'Values': ['22']},
                {'Name': 'to-port', 'Values': ['22']},
                {'Name': 'cidr', 'Values': ['0.0.0.0/0', '::/0']}
            ]
        )

        # Iterate over the rules and revoke if necessary
        for rule in response['SecurityGroupRules']:
            if rule['IsEgress'] == False and (rule['CidrIpv4'] == '0.0.0.0/0' or rule['CidrIpv6'] == '::/0'):
                client.revoke_security_group_ingress(
                    GroupId=security_group_id,
                    IpPermissions=[{
                        'IpProtocol': 'tcp',
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpRanges': [{'CidrIp': rule['CidrIpv4']}],
                        'Ipv6Ranges': [{'CidrIpv6': rule['CidrIpv6']}]
                    }]
                )
                print(f"Revoked unrestricted access on port 22 for Security Group: {security_group_id}")

    except Exception as e:
        print(f"Error processing Security Group: {security_group_id}")
        print(str(e))
        return {
            'statusCode': 500,
            'body': json.dumps('Error processing Security Group')
        }

    return {
        'statusCode': 200,
        'body': json.dumps('Successfully executed')
    }
EOF
  }
}

