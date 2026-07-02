.DEFAULT_GOAL := help
.PHONY: help up down restart build logs ps test lint fmt check secrets clean

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

up: ## Build and start the full stack (detached)
	docker compose up --build -d

down: ## Stop and remove the stack
	docker compose down

restart: ## Restart the proxy (reload nginx.conf / re-resolve upstreams)
	docker compose restart proxy

build: ## Build all service images
	docker compose build

logs: ## Tail logs of all services
	docker compose logs -f --tail 100

ps: ## Show container status
	docker compose ps

test: ## Run the test suite (env is set by tests/conftest.py)
	python -m pytest tests/ -v

lint: ## Lint with ruff + black (check only) — matches CI
	ruff check .
	black --check .

fmt: ## Auto-format: ruff --fix then black
	ruff check . --fix
	black .

check: lint test ## Lint + test (run before pushing)

secrets: ## Generate a .env with strong secrets from .env.example
	./scripts/generate-secrets.sh

clean: ## Remove caches and build artefacts
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache .coverage
