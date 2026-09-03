# Developer entry points (guide §20.2).
.DEFAULT_GOAL := help
SHELL := /bin/bash

PY ?= python3
VENV ?= .venv
BIN := $(VENV)/bin

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

$(BIN)/python:
	$(PY) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip

.PHONY: install
install: $(BIN)/python ## Install the app and development dependencies
	$(BIN)/pip install -e ".[documents,dev]"

.PHONY: bootstrap
bootstrap: install ## Create local config and development secrets
	@test -f .env || cp .env.example .env
	@$(BIN)/python scripts/bootstrap_env.py
	@echo "bootstrap complete — .env is git-ignored and must never hold production secrets"

.PHONY: up
up: ## Start gateway, PostgreSQL and the fake provider
	docker compose up --build -d
	@echo "gateway on http://localhost:8080  (readiness: /health/ready)"

.PHONY: up-gpu
up-gpu: ## Start the stack with the GPU-backed local model
	docker compose -f docker-compose.yml -f docker-compose.gpu.yml --profile gpu-model up --build -d

.PHONY: down
down: ## Stop local services
	docker compose down

.PHONY: migrate
migrate: ## Apply database migrations
	$(BIN)/python scripts/migrate.py

.PHONY: test
test: ## Run unit, integration and contract tests
	$(BIN)/pytest tests/unit tests/integration tests/contract -q

.PHONY: test-security
test-security: ## Run security and failure-injection tests
	$(BIN)/pytest tests/security tests/failure_injection -q

.PHONY: test-all
test-all: ## Run the whole suite
	$(BIN)/pytest -q

.PHONY: lint
lint: ## Format check, lint, type check and policy validation
	$(BIN)/ruff format --check .
	$(BIN)/ruff check .
	$(BIN)/mypy app
	$(BIN)/python scripts/check_policy.py config/policy.default.yaml

.PHONY: fmt
fmt: ## Apply formatting
	$(BIN)/ruff format .
	$(BIN)/ruff check --fix .

.PHONY: smoke
smoke: ## Exercise safe, sanitized, blocked and closed-scope paths against a running gateway
	$(BIN)/python scripts/smoke_test.py http://localhost:8080 dev-token-1

.PHONY: fake-provider
fake-provider: ## Run the recording fake provider locally
	$(BIN)/python scripts/fake_external.py
