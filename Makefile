PKG := mynewt.apache.org/imgmod/version
VERSION:="0.0.3"
DATE := $(shell date -u +%F,%R)
COMMIT := $(shell git rev-parse --short HEAD)
ifneq ($(shell git status --porcelain),)
    COMMIT_SUFFIX := "-dirty"
endif
GIT_STATE := ${COMMIT}${COMMIT_SUFFIX}

GOOS?=linux
GOARCH?=amd64

GWARCH=${GOOS}-${GOARCH}

all:
	@echo "Usage:"
	@echo "    make binary GOOS=linux   # Linux"
	@echo "    make binary GOOS=darwin  # MacOS"
	@echo "    make binary GOOS=windows # Windows"

.PHONY: version
version:
	@echo ${VERSION}

.PHONY: gitstate
gitstate:
	@echo ${GIT_STATE}

binary:
	@GOOS=${GOOS} GOARCH=${GOARCH} GO111MODULE=on go build -ldflags \
		"-X ${PKG}.Version=${VERSION} -X ${PKG}.BuildDate=${DATE} -X ${PKG}.GitState=${GIT_STATE}"
