.PHONY: debug-build release-build test fmt lint fmt-lint help

help:
	@echo "Available targets:"
	@echo "  debug-build   - Build the project in debug mode"
	@echo "  release-build - Build the project in release mode"
	@echo "  test          - Run all tests"
	@echo "  fmt           - Format the code"
	@echo "  lint          - Run clippy linter"
	@echo "  fmt-lint      - Format and lint the code"

build-debug:
	cargo build

build-release:
	cargo build --release

test:
	cargo test

fmt:
	cargo fmt

fmt-lint: fmt lint

lint:
	cargo clippy -- --deny warnings

lint-pedantic:
	cargo clippy -- --deny warnings --allow clippy::pedantic

lint-fix:
	cargo clippy --fix -- --deny warnings --allow clippy::pedantic
