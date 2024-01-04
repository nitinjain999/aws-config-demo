provider "aws" {
  region = "eu-north-1" # Change to your AWS region
}

# IAM Role for Lambda Function
resource "aws_iam_role" "lambda_role" {
  name = "lambda_role_for_security_group_remediation"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        },
      },
    ],
  })
}

# IAM Policy for Lambda Function
resource "aws_iam_role_policy" "lambda_policy" {
  name   = "lambda_policy_for_security_group_remediation"
  role   = aws_iam_role.lambda_role.id
  policy = data.aws_iam_policy_document.lambda_policy.json
}

data "aws_iam_policy_document" "lambda_policy" {
  statement {
    actions   = ["ec2:RevokeSecurityGroupIngress"]
    resources = ["*"]
  }
}

# Lambda Function for Remediation
resource "aws_lambda_function" "remediation_function" {
  filename         = data.archive_file.lambda_function.output_path
  function_name    = "security_group_remediation_function"
  role             = aws_iam_role.lambda_role.arn
  handler          = "index.lambda_handler"
  runtime          = "python3.8"
  source_code_hash = filebase64sha256(data.archive_file.lambda_function.output_path)
}

# AWS Config Rule to Detect the Issue
resource "aws_config_config_rule" "detect_open_ssh" {
  name        = "restricted-ssh"
  description = "Checks for unrestricted SSH access."

  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }
  scope {
    compliance_resource_types = ["AWS::EC2::SecurityGroup"]
  }

  depends_on = [aws_lambda_function.remediation_function]
}

resource "aws_ssm_document" "remediation_document" {
  name          = "SecurityGroupRemediationDocument"
  document_type = "Automation"

  content = jsonencode({
    schemaVersion = "0.3"
    description   = "Invoke Lambda function to remediate security group configuration"
    mainSteps = [
      {
        action = "aws:invokeLambdaFunction"
        name   = "invokeLambda"
        inputs = {
          FunctionName = aws_lambda_function.remediation_function.function_name
          Payload      = "{}"
        }
      }
    ]
  })
}

resource "aws_config_remediation_configuration" "remediate_open_ssh" {
  config_rule_name = aws_config_config_rule.detect_open_ssh.name

  target_id   = aws_ssm_document.remediation_document.id
  target_type = "SSM_DOCUMENT"

  parameter {
    name         = "AutomationAssumeRole"
    static_value = aws_iam_role.lambda_role.arn
  }

  depends_on = [aws_config_config_rule.detect_open_ssh]
}

# Outputs
output "lambda_function_name" {
  value = aws_lambda_function.remediation_function.function_name
}

output "config_rule_name" {
  value = aws_config_config_rule.detect_open_ssh.name
}
