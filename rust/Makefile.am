EXTRA_DIST =	src \
		.cargo/config.in \
		cbindgen.toml \
		gen/rust-bindings.h

if HAVE_CARGO_VENDOR
EXTRA_DIST +=	vendor
endif

if !DEBUG
RELEASE = --release
endif

if HAVE_LUA
RUST_FEATURES +=	lua $(LUA_INT8)
endif

if DEBUG
RUST_FEATURES +=	debug
endif

if DEBUG_VALIDATION
RUST_FEATURES +=	debug-validate
endif

if RUST_CROSS_COMPILE 
RUST_TARGET = --target $(host_triplet)
endif

all-local:
if HAVE_CBINDGEN
	cbindgen --config $(abs_top_srcdir)/rust/cbindgen.toml \
		--quiet --output $(abs_top_builddir)/rust/gen/rust-bindings.h
endif
if HAVE_CYGPATH
	@rustup_home@ \
		CARGO_HOME="$(CARGO_HOME)" \
		CARGO_TARGET_DIR="$(e_rustdir)/target" \
		$(CARGO) build $(RELEASE) \
			--features "$(RUST_FEATURES)" $(RUST_TARGET)
else
	@rustup_home@ \
		CARGO_HOME="$(CARGO_HOME)" \
		CARGO_TARGET_DIR="$(abs_top_builddir)/rust/target" \
		$(CARGO) build $(RELEASE) \
			--features "$(RUST_FEATURES)" $(RUST_TARGET)
endif

clean-local:
	rm -rf target
if HAVE_CBINDGEN
	rm -rf gen
endif

distclean-local:
	rm -f Cargo.lock

maintainerclean-local:
	rm -rf vendor gen

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
if HAVE_CBINDGEN
gen/rust-bindings.h:
	cbindgen --config $(abs_top_srcdir)/rust/cbindgen.toml \
		--quiet --output $(abs_top_builddir)/rust/gen/rust-bindings.h
else
gen/rust-bindings.h:
endif

doc:
	CARGO_HOME=$(CARGO_HOME) $(CARGO) doc --all-features --no-deps
