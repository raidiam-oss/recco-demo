# Makefile
#

include ../version.properties
VER=${VERSION}

ifdef CHANGE_ID
VER=PR-${CHANGE_ID}-SNAPSHOT
else
VER=${VERSION}.${BUILD_NUMBER}
endif

PKG=github.com/raidiam/recco-demo/authorizer
REPO_INFO=$(shell git config --get remote.origin.url)
DATE=$(shell date)

GOARCH=arm64

LDFLAGS=-X "$(PKG).Version=$(VER)" -X "$(PKG).BuildDate=$(DATE)" -X "$(PKG).RepoUrl=$(REPO_INFO)" -X "$(PKG).BuildUrl=$(BUILD_URL)"

.PHONY: build

build:
	@rm -f bootstrap recco-demo-${VER}-authorizer-function.zip
	@(GOARCH=arm64 GOOS=linux go build -ldflags '-s -w $(LDFLAGS)' -gcflags "all=-trimpath=$GOPATH" -o bootstrap && zip recco-demo-${VER}-authorizer-function.zip bootstrap)

build-local:
	@(rm -f bootstrap recco-demo-${VER}-authorizer-function.zip && GOARCH=arm64 GOOS=linux go build -ldflags '-s -w $(LDFLAGS)' -gcflags "all=-trimpath=$GOPATH" -o bootstrap && zip recco-demo-${VER}-authorizer-function.zip bootstrap)

build-debug-local:
	@rm -f app recco-demo-${VER}-authorizer-function.zip bootstrap
	@echo "#!/bin/bash" > bootstrap
	@echo "dlv --listen=:2345 --headless=true --api-version=2 --accept-multiclient exec ./app" >> bootstrap
	@chmod +x bootstrap
	@(go build -ldflags '$(LDFLAGS)' -gcflags "all=-N -l -trimpath=$GOPATH" -o app && zip recco-demo-${VER}-authorizer-function.zip bootstrap app)
