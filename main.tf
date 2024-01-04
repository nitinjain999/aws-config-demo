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
  name        = "detect-open-ssh"
  description = "Checks for unrestricted SSH access."

  source {
    owner             = "AWS"
    source_identifier = "EC2_SECURITY_GROUP_ALLOWED_INGRESS"
  }

  input_parameters = jsonencode({
    port       = "22",
    ipProtocol = "tcp"
  })

  scope {
    compliance_resource_types = ["AWS::EC2::SecurityGroup"]
  }

  depends_on = [aws_lambda_function.remediation_function]
}

# AWS Config Remediation Action
resource "aws_config_remediation_configuration" "remediate_open_ssh" {
  config_rule_name = aws_config_config_rule.detect_open_ssh.name

  target_id   = aws_lambda_function.remediation_function.arn
  target_type = "SSM_DOCUMENT"

  # Parameters for the Lambda function
  parameter {
    name         = "ExecutionRoleName"
    static_value = aws_iam_role.lambda_role.name
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
