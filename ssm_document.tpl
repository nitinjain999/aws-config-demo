{
    "schemaVersion": "0.3",
    "description": "Invoke Lambda function to remediate security group configuration",
    "mainSteps": [
      {
        "action": "aws:invokeLambdaFunction",
        "name": "invokeLambda",
        "inputs": {
          "FunctionName": "${lambda_function_name}",
          "Payload": "{}"
        }
      }
    ]
  }
  