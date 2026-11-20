# Policy Warden: an AgentCore Harness agent that checks an AWS account against a plain-English policy.
PYTHON := python3
POLICY ?= policy.example.md
APPROVE ?= ask

.PHONY: help install test lint format check deploy seed unseed run ui stress teardown clean

help:
	@echo "make install              Install Python packages"
	@echo "make test                 Offline: rule engine, tool schemas, gate Lambda decisions"
	@echo "make lint                 ruff check and format check"
	@echo "make check                lint + test"
	@echo "make deploy               Create or update guardrail, gate Lambda, roles, harness (AWS)"
	@echo "make seed                 Plant known violations in us-east-1 (two 1 GiB volumes, one SG)"
	@echo "make run                  Check the account against POLICY=$(POLICY), APPROVE=ask|all|none"
	@echo "make ui                   Web UI on http://127.0.0.1:8765: edit the policy, approve rules, read reports"
	@echo "make stress               Run the hostile prompts in stress/cases.json, write results/"
	@echo "make unseed               Delete the seeded resources"
	@echo "make teardown             Delete everything make deploy created"

install:
	$(PYTHON) -m pip install -r requirements.txt

test:
	$(PYTHON) -m unittest discover -s tests -v

lint:
	ruff check .
	ruff format --check .
	@echo "lint OK"

format:
	ruff format .

check: lint test

deploy:
	$(PYTHON) infra/deploy.py

seed:
	$(PYTHON) infra/seed.py up

unseed:
	$(PYTHON) infra/seed.py down

run:
	$(PYTHON) -m warden.agent --policy $(POLICY) --approve $(APPROVE) "Check this account against the policy."

ui:
	$(PYTHON) -m warden.web

stress:
	$(PYTHON) stress/run.py

teardown:
	$(PYTHON) infra/teardown.py

# Caches only. results/ holds stress-test evidence and is never cleaned.
clean:
	find . -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .ruff_cache
