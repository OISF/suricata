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

if !RUST_DEBUG
if !DEBUG
RELEASE = --release
endif
endif

if HAVE_LUA
RUST_FEATURES +=	lua
endif

if DEBUG
RUST_FEATURES +=	debug
endif

all-local:
if HAVE_PYTHON
	cd $(top_srcdir)/rust && $(HAVE_PYTHON) ./gen-c-headers.py
endif
if HAVE_CYGPATH
	rustpath=`cygpath -a -t mixed $(abs_top_builddir)`
	cd $(top_srcdir)/rust && \
		CARGO_HOME=$(CARGO_HOME) \
		CARGO_TARGET_DIR="$$rustpath/rust/target" \
		$(CARGO) build $(RELEASE) $(FROZEN) \
			--features "$(RUST_FEATURES)"
else
	cd $(top_srcdir)/rust && \
		CARGO_HOME=$(CARGO_HOME) \
		CARGO_TARGET_DIR=$(abs_top_builddir)/rust/target \
		$(CARGO) build $(RELEASE) $(FROZEN) \
			--features "$(RUST_FEATURES)"
endif

clean-local:
	-rm -rf target gen

distclean-local: clean-local
	rm -rf vendor gen Cargo.lock

check:
	CARGO_HOME=$(CARGO_HOME) $(CARGO) test

Cargo.lock: Cargo.toml
	CARGO_HOME=$(CARGO_HOME) $(CARGO) generate-lockfile

if HAVE_CARGO_VENDOR
vendor:
	CARGO_HOME=$(CARGO_HOME) $(CARGO) vendor > /dev/null
else
vendor:
endif

# Can only include the headers if we have Python to generate them.
if HAVE_PYTHON
EXTRA_DIST +=	gen/c-headers
gen/c-headers:
	cd $(top_srcdir)/rust && $(HAVE_PYTHON) ./gen-c-headers.py
else
gen/c-headers:
endif
else # HAVE_RUST

all-local clean-local check vendor gen/c-headers:

endif # HAVE_RUST
