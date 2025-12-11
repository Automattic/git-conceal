.PHONY: check-debug build-debug check-release build-release test fmt lint lint-pedantic lint-fix help

help:
	@echo "Available targets:"
	@echo "  check-debug    - Check the project in debug mode"
	@echo "  build-debug    - Build the project in debug mode"
	@echo "  check-release  - Check the project in release mode"
	@echo "  build-release  - Build the project in release mode"
	@echo "  test           - Run all tests"
	@echo "  fmt            - Format the code"
	@echo "  lint           - Run clippy linter"
	@echo "  lint-pedantic  - Run clippy with pedantic warnings"
	@echo "  lint-fix       - Run clippy and auto-fix issues"

check-debug:
	cargo check

build-debug:
	cargo build

check-release:
	cargo check --release

build-release:
	cargo build --release

test:
	cargo test

fmt:
	cargo fmt

lint:
	cargo clippy -- --deny warnings

lint-pedantic:
	cargo clippy -- --deny warnings --allow clippy::pedantic --warn missing_docs

lint-fix:
	cargo clippy --fix -- --deny warnings --allow clippy::pedantic
