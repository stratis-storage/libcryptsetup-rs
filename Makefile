ifeq ($(origin FEDORA_RELEASE), undefined)
else
  FEDORA_RELEASE_ARGS = --release=${FEDORA_RELEASE}
endif

ifeq ($(origin CLIPPY_FIX), undefined)
  CLIPPY_OPTS = --all-targets --no-deps
else
  CLIPPY_OPTS = --fix
endif

ifeq ($(origin MINIMAL), undefined)
  BUILD = build
else
  BUILD = minimal-versions build --direct
endif

IGNORE_ARGS ?=

${HOME}/.cargo/bin/cargo-audit:
	cargo install cargo-audit

audit: ${HOME}/.cargo/bin/cargo-audit
	PATH=${HOME}/.cargo/bin:${PATH} cargo audit -D warnings

check-typos:
	typos

build:
	cargo ${BUILD}

build-examples:
	cargo ${BUILD} --examples

test-compare-fedora-versions:
	echo "Testing that COMPARE_FEDORA_VERSIONS environment variable is set to a valid path"
	test -e "${COMPARE_FEDORA_VERSIONS}"

check-fedora-versions: test-compare-fedora-versions
	${COMPARE_FEDORA_VERSIONS} ${FEDORA_RELEASE_ARGS} ${IGNORE_ARGS}

clippy:
	(cd libcryptsetup-rs-sys && cargo clippy --all-features ${CARGO_OPTS})
	cargo clippy --all-features ${CARGO_OPTS}

docs-rust:
	cargo doc --no-deps --package libcryptsetup-rs --package libcryptsetup-rs-sys

docs-ci: docs-rust

fmt:
	cargo fmt

fmt-ci:
	cargo fmt -- --check

release:
	cargo build --release

test:
	RUST_BACKTRACE=1 cargo test -- --skip test_mutex_poisoning_panic

test-mutex:
	RUST_BACKTRACE=1 cargo test --features=mutex -- --skip test_mutex_poisoning_panic

test-mutex-guard:
	RUST_BACKTRACE=1 RUST_TEST_THREADS=1 cargo test --features=mutex test_mutex_poisoning_panic

# Loopback tests must have the mutex feature enabled because Rust runs the tests
# on multiple threads which will cause a panic if the mutex feature is not enabled.
test-loopback:
	RUST_BACKTRACE=1 RUST_TEST_THREADS=1 CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='sudo -E' cargo test --features=mutex -- --ignored --skip test_mutex_poisoning_panic

yamllint:
	yamllint --strict .github/workflows/*.yml

.PHONY:
	build
	check-fedora-versions
	check-typos
	clippy
	docs-rust
	docs-ci
	fmt
	fmt-ci
	release
	test
	test-mutex
	test-mutex-guard
	test-compare-fedora-versions
	test-loopback
	test-loopback-mutex
	yamllint
