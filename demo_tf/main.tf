# Define input variables
provider "aws" {
  region = "eu-north-1" # Change to your AWS region
}
variable "region" {
  description = "AWS region"
  type        = string
  default     = "eu-north-1"
}

variable "sns_topic_name" {
  description = "Provide SNS Topic Name."
  type        = string
  default     = "SgRule-Remediation"
}

variable "sns_topic_subscription" {
  description = "Provide email ID for subscription."
  type        = string
  default     = "nitin.jain@atg.se"
}

# Create an SNS topic
resource "aws_sns_topic" "my_sns_topic" {
  name = var.sns_topic_name
}
resource "aws_sns_topic_subscription" "my_sns_topic_subscription" {
  topic_arn = aws_sns_topic.my_sns_topic.arn
  protocol  = "email"
  endpoint  = var.sns_topic_subscription
}
# Create an IAM role for Lambda
resource "aws_iam_role" "lambda_execution_role" {
  name = "LambdaExecutionRole"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

# Attach an inline policy to the IAM role
resource "aws_iam_policy" "lambda_execution_policy" {
  name        = "LambdaExecutionRolePolicy"
  description = "Policy for Lambda execution role"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:*",
        "ec2:RevokeSecurityGroupIngress",
        "sts:GetCallerIdentity",
        "sns:Publish"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}

resource "aws_iam_policy_attachment" "lambda_execution_policy_attachment" {
  name       = "lambda_execution_policy_attachment"
  policy_arn = aws_iam_policy.lambda_execution_policy.arn
  roles      = [aws_iam_role.lambda_execution_role.name]
}

# Create a Lambda function source code archive
data "archive_file" "lambda_function" {
  type        = "zip"
  source_dir  = "${path.module}/lambda"
  output_path = "${path.module}/lambda_function.zip"
}

# Create a Lambda function
resource "aws_lambda_function" "sg_rule_remediation" {
  description      = "Lambda function to revoke SG rules"
  function_name    = "SgRule-Remediation"
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.9"
  timeout          = 300
  memory_size      = 128
  role             = aws_iam_role.lambda_execution_role.arn
  filename         = data.archive_file.lambda_function.output_path

  environment {
    variables = {
      region       = var.region
      snsTopicName = var.sns_topic_name
    }
  }

  depends_on = [aws_iam_policy_attachment.lambda_execution_policy_attachment]
}


# Create an EventBridge rule
resource "aws_cloudwatch_event_rule" "sg_rule_remediation_rule" {
  name                = "SgRuleRemediationRule"
  description         = "Event rule to trigger Lambda"
  event_pattern       = <<EOF
{
  "source": ["aws.ec2"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["ec2.amazonaws.com"],
    "eventName": ["AuthorizeSecurityGroupIngress"]
  }
}
EOF
}

# Create a target for the EventBridge rule (Lambda function)
resource "aws_cloudwatch_event_target" "sg_rule_remediation_target" {
  rule      = aws_cloudwatch_event_rule.sg_rule_remediation_rule.name
  target_id = "SgRuleRemediationTarget"
  arn       = aws_lambda_function.sg_rule_remediation.arn
}

# Grant permission for EventBridge to invoke the Lambda function
resource "aws_lambda_permission" "sg_rule_remediation_permission" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sg_rule_remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn   = aws_cloudwatch_event_rule.sg_rule_remediation_rule.arn
}
