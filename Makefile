MAIN:=cmd/main.go

# LDFLAGS
VERSION:=dev
#VERSION := $(shell git tag --sort=committerdate | tail -1)
COMMIT := $(shell git rev-parse HEAD)
DATE := $(shell date -u '+%Y-%m-%d')
LDFLAGS=-ldflags \
				" \
				-X github.com/MirantisContainers/dex-http-server/cmd/main.version=${VERSION} \
				-X github.com/MirantisContainers/dex-http-server/cmd/main.commit=${COMMIT} \
				-X github.com/MirantisContainers/dex-http-server/cmd/main.date=${DATE} \
				"
IMAGE_REPO ?= ghcr.io/mirantiscontainers
IMAGE_TAG_BASE ?= $(IMAGE_REPO)/dex-http-server
IMG ?= $(IMAGE_TAG_BASE):$(VERSION)

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: all
all: fmt vet build ## Do all the things

.PHONY: print-%
print-%:
	@echo $($*)

##@ Development

.PHONY: build
build: ## Build the binary
	@go build ${LDFLAGS} -o bin/dex-http-server ${MAIN}

.PHONY: run
run: ## Run the binary
	@go run ${LDFLAGS} ${MAIN}

.PHONY: clean
clean: ## Clean out the binary
	@rm -rf bin

##@ Docker

.PHONY: up
up: ## Run the project in docker containers
	@docker compose up --build

.PHONY: docker-build
docker-build: ## Build the docker image
	@docker build -t ${IMG} .

PLATFORMS ?= linux/arm64,linux/amd64
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	# copy existing Dockerfile and insert --platform=${BUILDPLATFORM} into Dockerfile.cross, and preserve the original Dockerfile
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	- docker buildx create --name project-v3-builder
	docker buildx use project-v3-builder
	- docker buildx build --push --platform=$(PLATFORMS) --tag ${IMG} -f Dockerfile.cross .
	- docker buildx rm project-v3-builder
	rm Dockerfile.cross

.PHONY: docker-clean
docker-clean: ## Clean out the docker image
	@docker image rm ${IMG}

##@ Testing

.PHONY: test
test: fmt vet static ## Run all tests

.PHONY: fmt
fmt: ## Run go fmt against code.
	@go fmt ${MAIN}

.PHONY: vet
vet: ## Run go vet against code.
	@go vet ${MAIN}

.PHONY: static
static: ## Run staticcheck against code.
	@staticcheck -checks "all" ${MAIN}

##@ Dependencies
.PHONY: download
download:
	@echo "Download go.mod dependencies"
	@go mod download

.PHONY: install-tools
install-tools: download
	@echo "Install tools from tools/tools.go"
	@cat tools/tools.go | grep _ | awk -F'"' '{print $$2}' | xargs -tI % go install %
