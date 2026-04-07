# ═══════════════════════════════════════════════════════════════════
# IntegriShield — Monorepo Makefile
# ═══════════════════════════════════════════════════════════════════

.DEFAULT_GOAL := help
SHELL := /bin/bash

# ── Paths ──────────────────────────────────────────────────────────
MODULES_DIR := modules
SHARED_DIR  := shared
ML_DIR      := ml

# ── Python ─────────────────────────────────────────────────────────
PYTHON ?= python3
PIP    ?= pip3

# ════════════════════════════════════════════════════════════════════
# Targets
# ════════════════════════════════════════════════════════════════════

.PHONY: help install install-dev lint type-check test test-unit test-cov poc poc-down poc-dev4 build clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ── Install ────────────────────────────────────────────────────────

install: ## Install all module + shared dependencies
	@echo "══ Installing shared libraries ══"
	$(PIP) install redis fastapi uvicorn pydantic pydantic-settings
	@echo "══ Installing ML dependencies ══"
	$(PIP) install -r $(ML_DIR)/requirements.txt 2>/dev/null || true
	@for dir in $(MODULES_DIR)/m*/; do \
		if [ -f "$$dir/requirements.txt" ]; then \
			echo "══ Installing $$(basename $$dir) ══"; \
			$(PIP) install -r "$$dir/requirements.txt"; \
		elif [ -f "$$dir/pyproject.toml" ]; then \
			echo "══ Installing $$(basename $$dir) ══"; \
			$(PIP) install -e "$$dir" 2>/dev/null || true; \
		fi \
	done
	@echo "✅ All dependencies installed"

install-dev: install ## Install dev tools (ruff, pytest, mypy)
	$(PIP) install ruff pytest mypy httpx

# ── Quality ────────────────────────────────────────────────────────

lint: ## Run ruff linter on all Python code
	@echo "══ Linting ══"
	$(PYTHON) -m ruff check $(MODULES_DIR) $(SHARED_DIR) apps/ scripts/ $(ML_DIR) --fix
	@echo "✅ Lint passed"

format: ## Auto-format all Python code with ruff
	$(PYTHON) -m ruff format $(MODULES_DIR) $(SHARED_DIR) apps/ scripts/ $(ML_DIR)

type-check: ## Run mypy type checking
	@echo "══ Type checking ══"
	$(PYTHON) -m mypy $(MODULES_DIR) $(SHARED_DIR) --ignore-missing-imports
	@echo "✅ Type check passed"

# ── Tests ──────────────────────────────────────────────────────────

test: ## Run all unit tests
	@echo "══ Running all tests ══"
	$(PYTHON) -m pytest $(MODULES_DIR) tests/ -v --tb=short
	@echo "✅ Tests passed"

test-unit: ## Run unit tests only
	$(PYTHON) -m pytest $(MODULES_DIR)/*/tests/unit/ -v --tb=short

test-cov: ## Run tests with coverage
	$(PYTHON) -m pytest $(MODULES_DIR) tests/ --cov=$(MODULES_DIR) --cov-report=term-missing

# ── POC ────────────────────────────────────────────────────────────

poc: ## Start full POC stack (all devs + Redis + Postgres)
	@echo "══ Starting IntegriShield POC ══"
	docker compose -f poc/docker-compose.yml up --build

poc-down: ## Stop POC stack
	docker compose -f poc/docker-compose.yml down -v

poc-dev4: ## Start Dev4 lightweight stack (Redis + Dashboard only)
	@echo "══ Starting Dev4 stack ══"
	docker compose -f poc/docker-compose.dev4.yml up --build

poc-local: ## Start Dev4 stack without Docker (Redis + backend + frontend)
	@echo "══ Starting local dev environment ══"
	@echo "Starting Redis..."
	@redis-server --daemonize yes --port 6379 || echo "Redis may already be running"
	@echo "Starting backend on :8787..."
	@$(PYTHON) apps/dashboard/backend/server.py &
	@echo "Starting frontend on :4173..."
	@$(PYTHON) -m http.server 4173 --directory apps/dashboard &
	@echo "Starting event producer..."
	@$(PYTHON) scripts/demo_event_producer.py --interval 2 &
	@echo ""
	@echo "✅ IntegriShield running locally"
	@echo "   Dashboard:  http://localhost:4173"
	@echo "   Backend:    http://localhost:8787"
	@echo ""

# ── Build ──────────────────────────────────────────────────────────

build: ## Build all Docker images
	@echo "══ Building Docker images ══"
	@for dir in $(MODULES_DIR)/m*/; do \
		if [ -f "$$dir/Dockerfile" ]; then \
			name=$$(basename $$dir); \
			echo "Building integrishield/$$name..."; \
			docker build -t "integrishield/$$name:latest" -f "$$dir/Dockerfile" .; \
		fi \
	done
	@echo "Building integrishield/dashboard-backend..."
	@docker build -t integrishield/dashboard-backend:latest -f apps/dashboard/backend/Dockerfile .
	@echo "✅ All images built"

# ── Train ──────────────────────────────────────────────────────────

train: ## Train ML model (Dev2 pipeline)
	@echo "══ Training anomaly detection model ══"
	$(PYTHON) $(ML_DIR)/data/seed/generate_seed_data.py
	$(PYTHON) $(ML_DIR)/training/train_model.py
	$(PYTHON) $(ML_DIR)/training/evaluate_model.py
	@echo "✅ Model trained"

# ── Clean ──────────────────────────────────────────────────────────

clean: ## Remove build artifacts and caches
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -name "dump.rdb" -delete 2>/dev/null || true
	@echo "✅ Clean"
