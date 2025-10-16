#!/bin/bash

sleep 10
if [ -z "${PROXY_HOST_TARGET:-}" ]; then
  API_NAME="${API_NAME:-Recco Demo API}"
  REGION="${REGION:-us-east-1}"
  EDGE="${EDGE:-http://localstack:4566}"

  API_ID=$(aws --endpoint-url "$EDGE" --region "$REGION" apigateway get-rest-apis \
    --query "items[?name=='$API_NAME'].id" --output text)

#  export PROXY_HOST_TARGET="http://localstack:4566/restapis/${API_ID}/v1/_user_request_"
  export PROXY_HOST_TARGET="http://localstack:4566/_aws/execute-api/${API_ID}/v1"
  echo "Resolved PROXY_HOST_TARGET=${PROXY_HOST_TARGET}"
fi

exec "$@"
