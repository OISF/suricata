EXTRA_DIST =	src \
		.cargo/config.in \
		gen-c-headers.py

if HAVE_RUST

if HAVE_CARGO_VENDOR
EXTRA_DIST +=	vendor
endif

if !RUST_DEBUG
if !DEBUG
RELEASE = --release
endif
endif

if HAVE_LUA
RUST_FEATURES +=	lua $(LUA_INT8)
endif

if DEBUG
RUST_FEATURES +=	debug
endif

if RUST_CROSS_COMPILE 
RUST_TARGET = --target $(host_triplet)
endif

all-local:
if HAVE_PYTHON
	cd $(top_srcdir)/rust && $(HAVE_PYTHON) ./gen-c-headers.py
endif
	@rustup_home@ \
		CARGO_HOME="$(CARGO_HOME)" \
		CARGO_TARGET_DIR="$(abs_top_builddir)/rust/target" \
		$(CARGO) build $(RELEASE) \
			--features "$(RUST_FEATURES)" $(RUST_TARGET)

clean-local:
	-rm -rf target gen

distclean-local: clean-local
	rm -rf vendor gen Cargo.lock

check:
	CARGO_HOME="$(CARGO_HOME)" @rustup_home@ \
            CARGO_TARGET_DIR="$(abs_top_builddir)/rust/target" \
            $(CARGO) test $(RELEASE) --features "$(RUST_FEATURES)"

if HAVE_CARGO_VENDOR
vendor:
	CARGO_HOME="$(CARGO_HOME)" @rustup_home@ $(CARGO) vendor > /dev/null
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
