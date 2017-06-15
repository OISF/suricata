EXTRA_DIST = 	Cargo.toml \
		src \
		.cargo/config.in \
		gen-c-headers.py

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
		$(HAVE_PYTHON) ./gen-c-headers.py && \
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

# Can only include the headers if we have Python to generate them.
if HAVE_PYTHON
EXTRA_DIST +=	gen/c-headers
gen/c-headers:
	cd $(top_srcdir)/rust && $(HAVE_PYTHON) ./gen-c-headers.py
else
gen/c-headers:
endif
