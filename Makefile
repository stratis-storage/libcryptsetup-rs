RUST_2018_IDIOMS = -D bare-trait-objects \
                   -D ellipsis-inclusive-range-patterns \
                   -D unused-extern-crates

DENY = -D warnings -D future-incompatible -D unused ${RUST_2018_IDIOMS}

build:
	RUSTFLAGS="${DENY}" cargo build

clippy:
	cargo clippy --all-targets --all-features -- -D warnings -D clippy::needless_borrow -A clippy::upper-case-acronyms -A clippy::from_over_into

docs-rust:
	cargo doc --no-deps --package libcryptsetup-rs --package libcryptsetup-rs-sys

docs-travis: docs-rust

fmt:
	cargo fmt

fmt-travis:
	cargo fmt -- --check

release:
	RUSTFLAGS="${DENY}" cargo build --release

test:
	RUSTFLAGS="${DENY}" RUST_BACKTRACE=1 cargo test

test-mutex:
	RUSTFLAGS="${DENY}" RUST_BACKTRACE=1 cargo test --features=mutex

test-loopback:
	RUSTFLAGS="${DENY}" RUST_BACKTRACE=1 RUST_TEST_THREADS=1 cargo test -- --ignored

test-loopback-mutex:
	RUSTFLAGS="${DENY}" RUST_BACKTRACE=1 RUST_TEST_THREADS=1 cargo test --features=mutex -- --ignored

yamllint:
	yamllint --strict .github/workflows/main.yml

.PHONY:
	build
	clippy
	docs-rust
	docs-travis
	fmt
	fmt-travis
	release
	test
	test-loopback
	yamllint
