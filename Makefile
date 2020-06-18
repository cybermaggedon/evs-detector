
# Create version tag from git tag
VERSION=$(shell git describe | sed 's/^v//')
REPO=cybermaggedon/evs-detector
DOCKER=docker
GO=GOPATH=$$(pwd)/go go

all: evs-detector build

evs-detector: detector.go go.mod go.sum
	${GO} build -o $@ detector.go

build: evs-detector
	${DOCKER} build -t ${REPO}:${VERSION} -f Dockerfile .
	${DOCKER} tag ${REPO}:${VERSION} ${REPO}:latest

push:
	${DOCKER} push ${REPO}:${VERSION}
	${DOCKER} push ${REPO}:latest


