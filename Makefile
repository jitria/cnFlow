.PHONY: all generate build build-agent build-manager docker docker-agent docker-manager clean

MODULE_DIR := cnFlow

all: generate build

## eBPF code generation
generate:
	cd $(MODULE_DIR) && go generate ./agent/attacher/...

## Build binaries
build: build-agent build-manager

build-agent:
	cd $(MODULE_DIR) && go build -o ../bin/agent ./agent/main.go

build-manager:
	cd $(MODULE_DIR) && go build -o ../bin/manager ./manager/main.go

## Docker images
docker: docker-agent docker-manager

docker-agent:
	docker build --target agent -t cnflow-agent:latest -f deployments/Dockerfile .

docker-manager:
	docker build --target manager -t cnflow-manager:latest -f deployments/Dockerfile .

## Cleanup
clean:
	rm -rf bin/
	cd $(MODULE_DIR) && go clean
