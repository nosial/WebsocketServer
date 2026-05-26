.PHONY: all build release debug test test-all check clippy fmt fmt-check clean install doc doc-open audit outdated size bench help

BINARY_NAME = websocket-server
BINARY_PATH = target/release/$(BINARY_NAME)

all: build

## build      — Build release binary (default)
build: release

release:
	cargo build --release

debug:
	cargo build

## test       — Run integration tests (sequential, port-isolated)
test:
	cargo test --test integration_test -- --nocapture

## test-all   — Run all tests including unit tests
test-all:
	cargo test -- --nocapture

## check      — Run cargo check (fast compilation check)
check:
	cargo check --release

## clippy     — Run clippy lints (warning-free)
clippy:
	cargo clippy --release --all-targets -- -D warnings

## fmt        — Format all code
fmt:
	cargo fmt --all

## fmt-check  — Check formatting
fmt-check:
	cargo fmt --all -- --check

## clean      — Remove build artifacts
clean:
	cargo clean

## install    — Install binary to ~/.cargo/bin
install:
	cargo install --path .

## doc        — Build documentation
doc:
	cargo doc --no-deps --document-private-items

## doc-open   — Build and open documentation in browser
doc-open:
	cargo doc --no-deps --document-private-items --open

## audit      — Run cargo-audit for vulnerability scanning (cargo install cargo-audit)
audit:
	cargo audit

## outdated   — Check for outdated dependencies (cargo install cargo-outdated)
outdated:
	cargo outdated

## size       — Show binary size
size: release
	@ls -lh $(BINARY_PATH)
	@strip $(BINARY_PATH) 2>/dev/null; ls -lh $(BINARY_PATH)
	@which cargo-size 2>/dev/null && cargo-size $(BINARY_PATH) || true
	@which bloat 2>/dev/null && cargo bloat --release || true
	@which twiggy 2>/dev/null && twiggy top -n 20 $(BINARY_PATH) || true

## bench      — Run benchmark tests (nightly only)
bench:
	cargo bench

## help       — Show this help
help:
	@echo 'Usage: make <target>'
	@echo ''
	@echo 'Targets:'
	@sed -n 's/^## //p' $(MAKEFILE_LIST)
