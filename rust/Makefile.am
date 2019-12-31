EXTRA_DIST =	Cargo.toml \
		src \
		.cargo/config.in \
		cbindgen.toml \
		gen/rust-bindings.h

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
RUST_FEATURES +=	lua $(LUA_INT8)
endif

if DEBUG
RUST_FEATURES +=	debug
endif

if RUST_CROSS_COMPILE 
RUST_TARGET = --target $(host_triplet)
endif

all-local: $(abs_top_builddir)/rust/Cargo.lock
if HAVE_CBINDGEN
	cbindgen --config $(abs_top_srcdir)/rust/cbindgen.toml \
		--quiet --output $(abs_top_builddir)/rust/gen/rust-bindings.h
endif
if HAVE_CYGPATH
	rustpath=`cygpath -a -t mixed $(abs_top_builddir)`
	@rustup_home@ \
		CARGO_HOME="$(CARGO_HOME)" \
		CARGO_TARGET_DIR="$$rustpath/rust/target" \
		$(CARGO) build $(RELEASE) $(FROZEN) \
			--features "$(RUST_FEATURES)" $(RUST_TARGET)
else
	@rustup_home@ \
		CARGO_HOME="$(CARGO_HOME)" \
		CARGO_TARGET_DIR="$(abs_top_builddir)/rust/target" \
		$(CARGO) build $(RELEASE) $(FROZEN) \
			--features "$(RUST_FEATURES)" $(RUST_TARGET)
endif

clean-local:
	rm -rf target
if !HAVE_RUST_HEADERS
	rm -rf gen
endif

distclean-local:
	rm -rf Cargo.lock

maintainerclean-local:
	rm -rf Cargo.lock vendor gen

check:
	CARGO_HOME="$(CARGO_HOME)" @rustup_home@
		$(CARGO) test --features "$(RUST_FEATURES)"

$(abs_top_builddir)/rust/Cargo.lock: $(abs_top_srcdir)/rust/Cargo.toml.in
	CARGO_HOME="$(CARGO_HOME)" @rustup_home@ $(CARGO) \
		generate-lockfile

if HAVE_CARGO_VENDOR
vendor:
	CARGO_HOME="$(CARGO_HOME)" @rustup_home@ $(CARGO) vendor > /dev/null
else
vendor:
endif

if !HAVE_RUST_HEADERS
gen/rust-bindings.h:
	cbindgen --config $(abs_top_srcdir)/rust/cbindgen.toml \
		--quiet --output $(abs_top_builddir)/rust/gen/rust-bindings.h
endif
