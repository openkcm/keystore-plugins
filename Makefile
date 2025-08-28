.PHONY: reuse-lint
reuse-lint:
	docker run --rm --volume $(PWD):/data fsfe/reuse lint

.PHONY: clean
clean:
	rm -fR bin
	rm -f cover.* *.out

.PHONY: build
build: clean
	go build -o ./bin/keystoreop/aws ./cmd/keystoreop/aws

.PHONY: lint
lint:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	golangci-lint run -v --fix

.PHONY: test
test:
	go test -race -coverprofile cover.out ./...

.PHONY: coverage
coverage: test
	go tool cover -html=cover.out

KEYSTORE_PLUGINS_NAME=keystore-plugins
KEYSTORE_PLUGINS_DEV_TARGET=dev
TAG := latest
IMAGE_NAME := $(KEYSTORE_PLUGINS_NAME)-$(KEYSTORE_PLUGINS_DEV_TARGET):$(TAG)
DOCKERFILE_DIR := .
DOCKERFILE_NAME := Dockerfile.$(KEYSTORE_PLUGINS_DEV_TARGET)
CONTEXT_DIR := .

# Target to build Docker image
.PHONY: docker-dev-build
docker-dev-build:
	go mod vendor
	docker build -f $(DOCKERFILE_DIR)/$(DOCKERFILE_NAME) -t $(IMAGE_NAME) $(CONTEXT_DIR)

.PHONY: tidy
tidy:
	go mod tidy
	go mod vendor

.PHONY: proto
proto:
	protoc --go_out=. --go_opt=module=github.com/openkcm/keystore-plugins \
		--go-grpc_out=./pkg/proto --go-grpc_opt=module=github.com/openkcm/keystore-plugins/pkg/proto proto/**/**/*.proto