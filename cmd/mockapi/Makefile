# Makefile
#

include ../../version.properties
VER=${VERSION}

ifdef CHANGE_ID
VER=PR-${CHANGE_ID}-SNAPSHOT
else
VER=${VERSION}.${BUILD_NUMBER}
endif

PKG=github.com/raidiam/recco-demo/mock-api
REPO_INFO=$(shell git config --get remote.origin.url)
DATE=$(shell date)

LDFLAGS=-X "$(PKG).Version=$(VER)" -X "$(PKG).BuildDate=$(DATE)" -X "$(PKG).RepoUrl=$(REPO_INFO)" -X "$(PKG).BuildUrl=$(BUILD_URL)"

checks:
	@staticcheck ./...
	@gosec ./...
	@go fmt ./...

clean:
	@( rm -f main reco-demo-${VER}-mock-api-function.zip)

build:
	@rm -f bootstrap reco-demo-${VER}-mock-api-function.zip
	@(GOARCH=arm64 GOOS=linux go build -ldflags '-s -w $(LDFLAGS)' -gcflags "all=-trimpath=$GOPATH" -o bootstrap && zip recco-demo-${VER}-mock-api-function.zip bootstrap)

test:
	@(go test -v -coverprofile=coverage.out && go tool cover -func=coverage.out )

test-and-report:
	@(go test -v -coverprofile=coverage.out -json > report.json && go tool cover -func=coverage.out)


build-local:
	@(rm -f bootstrap recco-demo-${VER}-mock-api-function.zip && GOARCH=arm64 GOOS=linux go build -ldflags '-s -w $(LDFLAGS)' -gcflags "all=-trimpath=$GOPATH" -o bootstrap && zip recco-demo-${VER}-mock-api-function.zip bootstrap)

.PHONY: clean build test test-and-report
