clippy:
	cargo clippy --all-targets --all-features -- -D warnings -D clippy::needless_borrow

fmt:
	cargo fmt

fmt-travis:
	cargo fmt -- --check

.PHONY:
	fmt
	fmt-travis
