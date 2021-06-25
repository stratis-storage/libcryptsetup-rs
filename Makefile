ifeq ($(origin MANIFEST_PATH), undefined)
else
  MANIFEST_PATH_ARGS = --manifest-path=${MANIFEST_PATH}
endif

RUST_2018_IDIOMS = -D bare-trait-objects \
                   -D ellipsis-inclusive-range-patterns \
                   -D unused-extern-crates

DENY = -D warnings -D future-incompatible -D unused ${RUST_2018_IDIOMS}

build:
	RUSTFLAGS="${DENY}" cargo build

check-fedora-versions:
	${COMPARE_FEDORA_VERSIONS} ${MANIFEST_PATH_ARGS} \
	--ignore-missing libcryptsetup-rs-sys

check-fedora-versions-sys:
	${COMPARE_FEDORA_VERSIONS} ${MANIFEST_PATH_ARGS}

verify-dependency-bounds:
	RUSTFLAGS="${DENY}" cargo build ${MANIFEST_PATH_ARGS} --all-features
	${SET_LOWER_BOUNDS} ${MANIFEST_PATH_ARGS}
	RUSTFLAGS="${DENY}" cargo build ${MANIFEST_PATH_ARGS} --all-features

verify-dependency-bounds-sys:
	RUSTFLAGS="${DENY}" cargo build ${MANIFEST_PATH_ARGS} --all-features
	${SET_LOWER_BOUNDS} ${MANIFEST_PATH_ARGS}
	RUSTFLAGS="${DENY}" cargo build ${MANIFEST_PATH_ARGS} --all-features

clippy:
	RUSTFLAGS="${DENY}" cargo clippy --all-targets --all-features -- -D clippy::needless_borrow -A clippy::upper-case-acronyms -A clippy::from_over_into

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
	yamllint --strict .github/workflows/*.yml

.PHONY:
	build
	check-fedora-versions
	check-fedora-versions-sys
	clippy
	docs-rust
	docs-travis
	fmt
	fmt-travis
	release
	test
	test-loopback
	verify-dependency-bounds
	verify-dependency-bounds-sys
	yamllint
