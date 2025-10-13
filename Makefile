.PHONY: build

include version.properties
VER=${VERSION}

ifdef CHANGE_ID
VER=PR-${CHANGE_ID}-SNAPSHOT
else
VER=${VERSION}.${BUILD_NUMBER}
endif

test:
	find . -name go.mod -execdir go test ./... -v -coverprofile=coverage.txt -covermode=atomic \;

build-local-mtls:
	@(cd cmd/mtls && make build-local)

build-local-authorizer:
	@(cd authorizer && make build-local)

build-local-api:
	@(cd cmd/mockapi && make build-local)

build-local: build-local-authorizer build-local-application build-local-alb-proxy

.PHONY: build build-local test test-opa generate

build:
	echo "Building authorizer"
	@(cd authorizer && make build)
	echo "Building mock-api"
	@(cd cmd/mockapi && make build)

docs:
	godoc -http=localhost:6060
