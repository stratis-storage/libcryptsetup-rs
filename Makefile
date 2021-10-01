ifeq ($(origin FEDORA_RELEASE), undefined)
else
  FEDORA_RELEASE_ARGS = --release=${FEDORA_RELEASE}
endif

ifeq ($(origin MANIFEST_PATH), undefined)
else
  MANIFEST_PATH_ARGS = --manifest-path=${MANIFEST_PATH}
endif

IGNORE_ARGS ?=

DENY = -D warnings -D future-incompatible -D unused -D rust_2018_idioms -D rust_2018_compatibility -D nonstandard_style

build:
	RUSTFLAGS="${DENY}" cargo build

test-compare-fedora-versions:
	echo "Testing that COMPARE_FEDORA_VERSIONS environment variable is set to a valid path"
	test -e "${COMPARE_FEDORA_VERSIONS}"

check-fedora-versions: test-compare-fedora-versions
	${COMPARE_FEDORA_VERSIONS} ${MANIFEST_PATH_ARGS} ${FEDORA_RELEASE_ARGS} ${IGNORE_ARGS}

SET_LOWER_BOUNDS ?=
test-set-lower-bounds:
	echo "Testing that SET_LOWER_BOUNDS environment variable is set to a valid path"
	test -e "${SET_LOWER_BOUNDS}"

verify-dependency-bounds: test-set-lower-bounds
	RUSTFLAGS="${DENY}" cargo build ${MANIFEST_PATH_ARGS} --all-features
	${SET_LOWER_BOUNDS} ${MANIFEST_PATH_ARGS}
	RUSTFLAGS="${DENY}" cargo build ${MANIFEST_PATH_ARGS} --all-features

verify-dependency-bounds-sys: test-set-lower-bounds
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
	RUSTFLAGS="${DENY}" RUST_BACKTRACE=1 cargo test -- --skip test_mutex_poisoning_panic

test-mutex:
	RUSTFLAGS="${DENY}" RUST_BACKTRACE=1 cargo test --features=mutex -- --skip test_mutex_poisoning_panic

test-mutex-guard:
	RUSTFLAGS="${DENY}" RUST_BACKTRACE=1 RUST_TEST_THREADS=1 cargo test --features=mutex test_mutex_poisoning_panic

# Loopback tests must have the mutex feature enabled because Rust runs the tests
# on multiple threads which will cause a panic if the mutex feature is not enabled.
test-loopback:
	RUSTFLAGS="${DENY}" RUST_BACKTRACE=1 RUST_TEST_THREADS=1 cargo test --features=mutex -- --ignored --skip test_mutex_poisoning_panic

yamllint:
	yamllint --strict .github/workflows/*.yml

.PHONY:
	build
	check-fedora-versions
	clippy
	docs-rust
	docs-travis
	fmt
	fmt-travis
	release
	test
	test-mutex
	test-mutex-guard
	test-compare-fedora-versions
	test-loopback
	test-loopback-mutex
	test-set-lower-bounds
	verify-dependency-bounds
	verify-dependency-bounds-sys
	yamllint
