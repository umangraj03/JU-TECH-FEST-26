.PHONY: setup seed test dev help

help:
	@echo "Available commands:"
	@echo "  make setup - Install backend and frontend dependencies"
	@echo "  make seed  - Populate SQLite database with fictional records and attacks"
	@echo "  make test  - Run full Pytest security test suite"
	@echo "  make dev   - Start both backend and frontend development servers"

setup:
	python run.py setup

seed:
	python run.py seed

test:
	python run.py test

dev:
	python run.py dev
