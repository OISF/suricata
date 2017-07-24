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

if HAVE_LUA
RUST_FEATURES +=	lua
endif

if HAVE_RUST_EXTERNAL
RUST_FEATURES +=	experimental
endif

all-local:
if HAVE_PYTHON
	cd $(top_srcdir)/rust && \
		$(HAVE_PYTHON) ./gen-c-headers.py && \
		CARGO_TARGET_DIR=$(abs_builddir)/target \
		CARGO_HOME=$(CARGO_HOME) $(CARGO) build $(RELEASE) $(FROZEN) \
			--features "$(RUST_FEATURES)"
else
	cd $(top_srcdir)/rust && CARGO_TARGET_DIR=$(abs_builddir)/target \
		CARGO_HOME=$(CARGO_HOME) $(CARGO) build $(RELEASE) $(FROZEN) \
			--features "$(RUST_FEATURES)"
endif

clean-local:
	cd $(top_srcdir)/rust && CARGO_TARGET_DIR=$(abs_builddir)/target \
		CARGO_HOME=$(CARGO_HOME) $(CARGO) clean

distclean-local:
	rm -rf vendor gen Cargo.lock

check:
	cd $(top_srcdir)/rust && CARGO_TARGET_DIR=$(abs_builddir)/target \
		CARGO_HOME=$(CARGO_HOME) $(CARGO) test

Cargo.lock: Cargo.toml
	CARGO_HOME=$(CARGO_HOME) $(CARGO) generate-lockfile

if HAVE_CARGO_VENDOR
vendor:
	CARGO_HOME=$(CARGO_HOME) $(CARGO) vendor > /dev/null
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
