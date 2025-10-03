# Recco Demo Mock API Service
A minimal HTTP API designed to run as an AWS Lambda function behind API Gateway. It exposes two domain endpoints that enforce OAuth2-style scopes, uses DynamoDB for persistence, and includes structured logging and request tracing.

## Mutual TLS (mTLS) server
An mTLS server is available under /cmd/mtls to terminate TLS and enforce client certificate authentication. Typical usage:
- Listens on port 443 and requires clients to present a valid certificate issued by a trusted CA.
- Validates client certs against a configured CA bundle (trust store).
- Uses a server certificate and private key for TLS termination.
- Can be deployed side-by-side with the API to front traffic and forward to upstream services.

## Features
- AWS Lambda HTTP handler via aws-lambda-go-api-proxy
- Endpoints:
    - GET /recco/customer/v1/customer (requires scope: customer)
    - GET /recco/energy/v1/energy (requires scope: energy)
    - GET /health (liveness)

- Scope-based authorization:
    - Reads scopes from API Gateway authorizer context when deployed behind API Gateway
    - Falls back to Authorization: Bearer token parsing for local/dev use

- x-fapi-interaction-id header enforcement:
    - Must be UUIDv4 if provided; otherwise generated and echoed back

## Requirements
- Go 1.24
- AWS account (for cloud mode) or LocalStack (for local DynamoDB)
- Docker (optional, for container build/run)

## Environment variables
- AWS_LOCAL: set to true to run against LocalStack for DynamoDB (default: false)
- REGION: AWS region to use (e.g., eu-west-1)
- POPULATE_DB: set to true to auto-create mock items in DynamoDB at startup (local convenience)

When AWS_LOCAL=true, the service uses:
- DynamoDB endpoint: [http://localstack.local:4566](http://localstack.local:4566)
- Static credentials: test/test

## Running locally
Option A: Go build/run
- This Lambda-oriented service is designed for API Gateway/Lambda. For local invocation you typically run with a Lambda runtime emulator (e.g., aws-lambda-rie) or SAM CLI.

Example with AWS SAM (simplified outline):
- Create a SAM template wiring API Gateway → Lambda (runtime: provided.al2, image-based or binary handler).
- Set env vars (AWS_LOCAL, REGION, POPULATE_DB).
- Run: sam local start-api

Option B: Docker container
- The provided Dockerfile builds a minimal image suitable for local or image-based Lambda deployment.

Build:
- docker build -t mockapi:local .

Run against LocalStack:
- docker network create localstack || true
- docker run --rm -p 443:443
  --network localstack
  -e AWS_LOCAL=true
  -e REGION=eu-west-1
  -e POPULATE_DB=true
  --name mockapi
  mockapi:local

Notes:
- The container exposes port 443.
- Ensure LocalStack is reachable on the same Docker network as localstack.local:4566.

## Authorization and scopes
Each protected endpoint requires specific scopes:
- /recco/customer/v1/customer → customer
- /recco/energy/v1/energy → energy

How scopes are resolved:
1. When behind API Gateway, the handler reads them from the custom authorizer context (scope as a space-delimited string).
2. Otherwise, it falls back to parsing the Authorization: Bearer token.

Accepted token formats for local/dev:
- JWT with a space-delimited scope claim in payload.
- A JSON string token that includes one of:
    - scope: "s1 s2"
    - scopes: ["s1","s2"]
    - permissions: ["s1","s2"]

Examples:
- JWT payload idea (pseudo): { "sub":"123", "scope":"customer energy" }
- JSON-string token example for customer: {"active":true,"scopes":["customer"]}

In practice, set an Authorization header like:
- Authorization: Bearer {"active":true,"scopes":["customer"]}

Responses on failure:
- 401 if Authorization is missing/invalid or introspection-style JSON cannot be parsed
- 403 if token is valid but lacks required scopes

## x-fapi-interaction-id
- If the client sets x-fapi-interaction-id, it must be a valid UUIDv4; otherwise the request is rejected with 400.
- If missing, the server generates a UUIDv4 and echoes it in the response header.

## DynamoDB data
- On startup, if POPULATE_DB=true, the service inserts mock items:
    - One customer with a fixed ID used by /recco/customer/v1/customer
    - Several energy items with different IDs; /recco/energy/v1/energy returns a random one

- If items are missing, endpoints return 404.

Ensure your DynamoDB table(s) and item schema match the expectations from the codebase (customer and energy items with ID as the key). For LocalStack, create tables beforehand or rely on your helper tooling that may create them automatically.

## Example requests (local)
Customer (requires customer scope):
- curl -i [https://localhost:443/recco/customer/v1/customer](https://localhost:443/recco/customer/v1/customer)
  -H 'x-fapi-interaction-id: 3fa85f64-5717-4562-b3fc-2c963f66afa6'
  -H 'Authorization: Bearer {"active":true,"scopes":["customer"]}'

Energy (requires energy scope):
- curl -i [https://localhost:443/recco/energy/v1/energy](https://localhost:443/recco/energy/v1/energy)
  -H 'Authorization: Bearer {"scope":"energy"}'

Missing or invalid x-fapi-interaction-id:
- If you pass x-fapi-interaction-id with an invalid format, you will get 400.
- If you omit it, the response will include a generated x-fapi-interaction-id.

## Deployment
Container image (typical for Lambda):
- Build and push the image to ECR.
- Create/update a Lambda function using the container image.
- Configure an API Gateway HTTP API or REST API to route to the Lambda.
- Configure a custom authorizer (if applicable) to provide the scope field in the authorizer context.
- Set env vars (REGION, POPULATE_DB as needed; do not set AWS_LOCAL in production).

IAM and permissions:
- The Lambda role must allow access to DynamoDB (read/write as needed for your tables).

## Troubleshooting
- 401 Unauthorized: Missing Authorization header, malformed token, or token content cannot be parsed for scopes.
- 403 Forbidden: Token valid but does not include required scope.
- 400 Bad Request: x-fapi-interaction-id provided but not a valid UUIDv4.
- 404 Not Found: No matching data in DynamoDB (ensure POPULATE_DB or seed data).
- DynamoDB local connection issues: Verify Docker network and that LocalStack is reachable at [http://localstack.local:4566](http://localstack.local:4566) with AWS_LOCAL=true.
