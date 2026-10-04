.PHONY: help build build-cli build-all run demo test test-race lint localstack-up localstack-down tf-init tf-plan tf-apply tf-destroy clean

APP_NAME = vaultgate
CLI_NAME = vaultgate-cli
BIN_DIR = bin

help:
	@echo "VaultGate Development Commands:"
	@echo "  make build            - Build gateway binary"
	@echo "  make build-cli        - Build CLI verification tool"
	@echo "  make build-all        - Build both gateway and CLI binaries"
	@echo "  make run              - Run the gateway locally"
	@echo "  make demo             - Run automated security demonstration"
	@echo "  make test             - Run unit tests"
	@echo "  make test-race        - Run unit tests with race detector"
	@echo "  make localstack-up    - Start LocalStack in background"
	@echo "  make localstack-down  - Stop LocalStack"
	@echo "  make tf-init          - Initialize Terraform"
	@echo "  make tf-plan          - Run Terraform plan"
	@echo "  make tf-apply         - Apply Terraform configuration"
	@echo "  make clean            - Remove build artifacts and test cache"

build:
	@mkdir -p $(BIN_DIR)
	go build -v -o $(BIN_DIR)/$(APP_NAME) ./cmd/gateway

build-cli:
	@mkdir -p $(BIN_DIR)
	go build -v -o $(BIN_DIR)/$(CLI_NAME) ./cmd/cli

build-all: build build-cli

run: build
	./$(BIN_DIR)/$(APP_NAME)

demo: build-cli
	./$(BIN_DIR)/$(CLI_NAME) demo

test:
	go test -v ./...

test-race:
	go test -v -race ./...

localstack-up:
	docker compose up -d

localstack-down:
	docker compose down

tf-init:
	cd terraform && terraform init

tf-plan:
	cd terraform && terraform plan

tf-apply:
	cd terraform && terraform apply -auto-approve

tf-destroy:
	cd terraform && terraform destroy -auto-approve

clean:
	rm -rf $(BIN_DIR) .terraform.lock.hcl terraform/.terraform
