#!/bin/bash

unset AWS_PROFILE AWS_VAULT
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_SESSION_TOKEN=test
export AWS_REGION=us-east-1

# Exit immediately if any command fails.
set -e

if ! awslocal dynamodb describe-table --table-name energy --region "$AWS_REGION" >/dev/null 2>&1; then
  echo "Creating energy table..."
  awslocal dynamodb create-table --cli-input-json '{
      "TableName": "energy",
      "AttributeDefinitions": [
          {
              "AttributeName": "id",
              "AttributeType": "S"
          }
      ],
      "KeySchema": [
          {
              "AttributeName": "id",
              "KeyType": "HASH"
          }
      ],
      "BillingMode": "PAY_PER_REQUEST"
  }'

  awslocal dynamodb wait table-exists --table-name energy --region "$AWS_REGION"
else
  echo "energy table already exists"
fi

if ! awslocal dynamodb describe-table --table-name customers --region "$AWS_REGION" >/dev/null 2>&1; then
  echo "Creating table customer..."
  awslocal dynamodb create-table --region "$AWS_REGION" --cli-input-json '{
    "TableName": "customers",
    "BillingMode": "PAY_PER_REQUEST",
    "AttributeDefinitions": [
      { "AttributeName": "id", "AttributeType": "S" }
    ],
    "KeySchema": [
      { "AttributeName": "id", "KeyType": "HASH" }
    ]
  }'

  awslocal dynamodb wait table-exists --table-name customers --region "$AWS_REGION"
else
  echo "clients table already exists"
fi

if ! awslocal dynamodb describe-table --table-name readings --region "$AWS_REGION" >/dev/null 2>&1; then
  echo "Creating table readings..."
  awslocal dynamodb create-table --region "$AWS_REGION" --cli-input-json '{
    "TableName": "readings",
    "BillingMode": "PAY_PER_REQUEST",
    "AttributeDefinitions": [
      { "AttributeName": "mpxn", "AttributeType": "S" },
      { "AttributeName": "ts", "AttributeType": "S" }
    ],
    "KeySchema": [
      { "AttributeName": "mpxn", "KeyType": "HASH" },
      { "AttributeName": "ts", "KeyType": "RANGE" }
    ]
  }'

  awslocal dynamodb wait table-exists --table-name readings --region "$AWS_REGION"
else
  echo "readings table already exists"
fi

# Create/get IAM role for Lambda
echo "Ensuring IAM role '$ROLE_NAME' exists..."
if ! ROLE_ARN="$(awslocal iam get-role --role-name "authorizer-lambda-role" --query 'Role.Arn' --output text 2>/dev/null)"; then
  TRUST_POLICY='{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": { "Service": "lambda.amazonaws.com" },
        "Action": "sts:AssumeRole"
      }
    ]
  }'
  ROLE_ARN="$(awslocal iam create-role \
    --role-name "authorizer-lambda-role" \
    --assume-role-policy-document "$TRUST_POLICY" \
    --query 'Role.Arn' \
    --output text)"
  # Attach basic execution policy (recognized by LocalStack)
  awslocal iam attach-role-policy \
    --role-name "authorizer-lambda-role" \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole >/dev/null
  echo "Created IAM role: $ROLE_ARN"
else
  echo "Using existing IAM role: $ROLE_ARN"
fi

awslocal ssm put-parameter \
  --name "/recco-demo/ca-crt" \
  --type "SecureString" \
  --value "$(cat /keys/ca_trusted_list.pem)" \
  --overwrite

awslocal ssm put-parameter \
  --name "/recco-demo/server-key" \
  --type "SecureString" \
  --value "$(cat /keys/server.key)" \
  --overwrite

awslocal ssm put-parameter \
  --name "/recco-demo/server-crt" \
  --type "SecureString" \
  --value "$(cat /keys/server.crt)" \
  --overwrite

INTROSPECTION_ENDPOINT="https://matls-auth.directory.recco.raidiam.io/token/introspection"
USER_INFO_ENDPOINT="https://matls-auth.directory.recco.raidiam.io/me"
CLIENT_ID="https://rp.directory.recco.raidiam.io/openid_relying_party/febaf72c-1a00-4fb3-9330-bd2b9000e03e"
CLIENT_CERT_HEADER="TLS-Certificate"
SSM_TRANSPORT_CERTIFICATE_NAME="/recco-demo/server-crt"
SSM_TRANSPORT_KEY_NAME="/recco-demo/server-key"
SSM_CA_TRUSTED_LIST_NAME="/recco-demo/ca-crt"
ENV_VARS="Variables={LOG_LEVEL=TRACE,AWS_REGION=${AWS_REGION},CLIENT_CERT_HEADER=${CLIENT_CERT_HEADER},AWS_LOCAL=true,LOCALSTACK_ENDPOINT=http://localhost:4566,AWS_ACCESS_KEY_ID=fake,AWS_SECRET_ACCESS_KEY=fake,KMS_KEY_ID=alias/authorizer-key,INTROSPECTION_ENDPOINT=${INTROSPECTION_ENDPOINT},CLIENT_ID=${CLIENT_ID},USER_INFO_ENDPOINT=${USER_INFO_ENDPOINT},SSM_TRANSPORT_CERTIFICATE_NAME=${SSM_TRANSPORT_CERTIFICATE_NAME},SSM_TRANSPORT_KEY_NAME=${SSM_TRANSPORT_KEY_NAME},SSM_CA_TRUSTED_LIST_NAME=${SSM_CA_TRUSTED_LIST_NAME}}"

echo "Creating Lambda function 'authorizer'..."
awslocal lambda create-function \
    --function-name "authorizer" \
    --runtime "provided.al2" \
    --handler "bootstrap" \
    --role "$ROLE_ARN" \
    --zip-file "fileb:///builds/authorizer/recco-demo-1.0.0.authorizer-function.zip" \
    --environment "$ENV_VARS" \
    --timeout 30 \
    --region "$AWS_REGION" >/dev/null

echo "Lambda 'authorizer' created."
echo "Done. Function: authorizer, Region: $AWS_REGION"
echo "Tip: invoke via -> awslocal lambda invoke --function-name authorizer --payload '{}' out.json --region $AWS_REGION && cat out.json"

ENV_VARS="Variables={AWS_LOCAL=true,LOG_LEVEL=TRACE,REGION=${AWS_REGION},POPULATE_DB=true}"
echo "Creating Lambda function 'mock'..."
awslocal lambda create-function \
    --function-name "mock" \
    --runtime "provided.al2" \
    --handler "bootstrap" \
    --role "$ROLE_ARN" \
    --zip-file "fileb:///builds/mock/recco-demo-1.0.0.mock-api-function.zip" \
    --environment "$ENV_VARS" \
    --timeout 30 \
    --region "$AWS_REGION" >/dev/null

echo "Lambda 'mock' created."
echo "Done. Function: mock, Region: $AWS_REGION"
echo "Tip: invoke via -> awslocal lambda invoke --function-name mock --payload '{}' out.json --region $AWS_REGION && cat out.json"

echo "Fetching Lambda ARN for function 'authorizer'..."
AUTH_LAMBDA_ARN="$(awslocal lambda get-function --function-name "authorizer" --region "$AWS_REGION" --query 'Configuration.FunctionArn' --output text)"

echo "Fetching Lambda ARN for function 'mock'..."
API_LAMBDA_ARN="$(awslocal lambda get-function --function-name "mock" --region "$AWS_REGION" --query 'Configuration.FunctionArn' --output text)"

 sed -e "s|\${demo_service_invoke_arn}|arn:aws:apigateway:$AWS_REGION:lambda:path/2015-03-31/functions/$API_LAMBDA_ARN:\$LATEST/invocations|g" \
     -e "s|\${authorizer_invoke_arn}|arn:aws:apigateway:$AWS_REGION:lambda:path/2015-03-31/functions/$AUTH_LAMBDA_ARN/invocations|g" \
     /builds/openapi/api.yml > /builds/openapi/apib.yaml

echo "Importing OpenAPI into API Gateway v2 (HTTP API)..."
 REST_API_ID="$(awslocal apigateway import-rest-api \
    --body "file:///builds/openapi/apib.yaml" \
    --region "$AWS_REGION" \
    --query 'id' --output text)"
  echo "Created HTTP API: $REST_API_ID"

# Create a deployment and stage
  DEPLOYMENT_ID="$(awslocal apigateway create-deployment \
    --rest-api-id "$REST_API_ID" \
    --stage-name "v1" \
    --region "$AWS_REGION" \
    --query 'id' --output text)"
  echo "Deployment: $DEPLOYMENT_ID"


  # HTTP API base URL in LocalStack
  INVOKE_URL="http://localstack:4566/restapis/${REST_API_ID}/v1/_user_request_/"
  echo "Invoke URL: $INVOKE_URL"

# Authorizer permission
awslocal  lambda add-permission \
  --function-name authorizer \
  --statement-id apigw-authorizer \
  --action lambda:InvokeFunction \
  --principal apigateway.amazonaws.com \
  --source-arn arn:aws:execute-api:${AWS_REGION}:000000000000:${REST_API_ID}/*
