EXTRA_DIST = 	Cargo.toml \
		src \
		.cargo/config.in \
		gen-c-headers.py \
		gen/c-headers

if HAVE_RUST
EXTRA_DIST +=	Cargo.lock \
		vendor
endif

if HAVE_RUST_VENDOR
FROZEN = --frozen
endif

if !DEBUG
RELEASE = --release
endif

gen/c-headers:
if HAVE_PYTHON
	cd $(top_srcdir)/rust && python ./gen-c-headers.py
else
	@echo "python not available, will not generate headers"
endif

if HAVE_RUST

FEATURES =

if HAVE_LUA
FEATURES +=	lua
endif

all-local:
if HAVE_PYTHON
	cd $(top_srcdir)/rust && CARGO_TARGET_DIR=$(abs_builddir)/target \
		python ./gen-c-headers.py && \
		cargo build $(RELEASE) $(FROZEN) --features "$(FEATURES)"
else
	cd $(top_srcdir)/rust && CARGO_TARGET_DIR=$(abs_builddir)/target \
		cargo build $(RELEASE) $(FROZEN) --features "$(FEATURES)"
endif

clean-local:
	cd $(top_srcdir)/rust && CARGO_TARGET_DIR=$(abs_builddir)/target \
		cargo clean

distclean-local:
	rm -rf vendor
	rm -rf gen

check:
	cd $(top_srcdir)/rust && CARGO_TARGET_DIR=$(abs_builddir)/target \
		cargo test

Cargo.lock: Cargo.toml
	cargo update
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
