EXTRA_DIST = 	Cargo.toml \
		Cargo.lock \
		src/lib.rs \
		.cargo/config.in

if HAVE_RUST
EXTRA_DIST +=	vendor
endif

if HAVE_RUST_VENDOR
FROZEN = --frozen
endif

if !DEBUG
RELEASE = --release
endif

if HAVE_RUST

FEATURES =

if HAVE_LUA
FEATURES +=	lua
endif

all-local:
	cd $(top_srcdir)/rust && CARGO_TARGET_DIR=$(abs_builddir)/target \
		cargo build $(RELEASE) $(FROZEN) --features "$(FEATURES)"

clean-local:
	cd $(top_srcdir)/rust && CARGO_TARGET_DIR=$(abs_builddir)/target \
		cargo clean

distclean-local:
	rm -rf vendor

check:
	cd $(top_srcdir)/rust && CARGO_TARGET_DIR=$(abs_builddir)/target \
		cargo test
else
all-local clean-local check:
endif

if HAVE_CARGO_VENDOR
vendor:
	cargo vendor > /dev/null
else
vendor:
	@echo "error: cargo vendor not installed"
	exit 1
endif
