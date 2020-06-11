
# Create version tag from git tag
VERSION=$(shell git describe | sed 's/^v//')
REPO=cybermaggedon/evs-detector
DOCKER=docker
GO=GOPATH=$$(pwd)/go go

all: evs-detector build

evs-detector: evs-detector.go go.mod go.sum
	${GO} build evs-detector.go

build: evs-detector
	${DOCKER} build -t ${REPO}:${VERSION} -f Dockerfile .

push:
	${DOCKER} push ${REPO}:${VERSION}
