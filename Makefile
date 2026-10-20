.PHONY: release test

release:
	cargo build --release

test:
	cargo test --release
