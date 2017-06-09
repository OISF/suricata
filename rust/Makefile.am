EXTRA_DIST = 	Cargo.toml \
		src \
		.cargo/config.in \
		gen-c-headers.py \
		gen/c-headers

if HAVE_RUST

EXTRA_DIST +=	Cargo.lock

if HAVE_CARGO_VENDOR
EXTRA_DIST +=	vendor
endif

if HAVE_RUST_VENDOR
FROZEN = --frozen
endif

if !DEBUG
RELEASE = --release
endif

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

if HAVE_CARGO_VENDOR
vendor:
	cargo vendor > /dev/null
else
vendor:
endif

else # HAVE_RUST

all-local clean-local check vendor:

endif # HAVE_RUST

gen/c-headers:
if HAVE_PYTHON
	cd $(top_srcdir)/rust && python ./gen-c-headers.py
else
	@echo "python not available, will not generate headers"
endif
