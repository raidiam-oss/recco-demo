# Step 1: Build Stage.
FROM golang:1.24-alpine AS builder

ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

WORKDIR /app

COPY . /app

COPY ./cmd/mtls/entrypoint.sh /app

RUN go mod download

RUN go build -o main ./cmd/mtls

# Step 2: Run Stage.
FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/main ./main
COPY --from=builder /app/entrypoint.sh ./entrypoint.sh
RUN apk add --no-cache aws-cli

RUN chmod +x ./entrypoint.sh
EXPOSE 443

ENTRYPOINT [ "/bin/sh", "./entrypoint.sh" ]

CMD [ "./main" ]
