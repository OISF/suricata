EXTRA_DIST = Cargo.toml \
	     src/lib.rs

if BUILD_RUST
all-local:
	cargo build --release

clean-local:
	-cargo clean

check:
	cargo test
endif
