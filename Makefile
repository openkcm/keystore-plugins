.PHONY: clean
clean:
	rm -fR bin
	rm -f cover.* *.out
	rm -f junit.xml

.PHONY: build
build: clean
	go build -o ./bin/keystoreop/aws ./cmd/keystoreop/aws

.PHONY: lint
lint:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	golangci-lint run -v --fix

.PHONY: test
test: install-gotestsum
	gotestsum --format testname --junitfile junit.xml -- -race -coverprofile cover.out ./...
	go tool cover -func cover.out | awk '/^total:/ {printf "Coverage: %s\n", $$3}'

.PHONY: install-gotestsum
install-gotestsum:
	(cd /tmp && go install gotest.tools/gotestsum@latest)

.PHONY: coverage
coverage: test
	go tool cover -html=cover.out

# List of folders to format
FORMAT_FOLDERS := \
    ./

# Format Go files in specified folders
.PHONY: format-go
format-go:
	for dir in $(FORMAT_FOLDERS); do \
		find $$dir -name "*.go" -exec sh -c \
			'gofmt -w "$$1" && \
			goimports -w "$$1" && \
			golines -w "$$1" && \
			gci write --skip-generated \
				-s standard \
				-s default \
				-s "prefix(github.tools.sap/kms/plugin-sdk)" \
				-s blank \
				-s dot \
				-s alias \
				-s localmodule \
				"$$1"' sh {} \; ; \
	done

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
		--go-grpc_out=./pkg/proto --go-grpc_opt=module=github.com/openkcm/keystore-plugins/pkg/proto proto/*.proto