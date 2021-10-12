EXTRA_DIST =	src \
		.cargo/config.in \
		cbindgen.toml \
		dist/rust-bindings.h

if HAVE_CARGO_VENDOR
EXTRA_DIST +=	vendor
endif

if !DEBUG
RELEASE = --release
endif

if RUST_BUILD_STD
NIGHTLY_ARGS = -Z build-std
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

if HTTP2_DECOMPRESSION
RUST_FEATURES +=	decompression
endif

if HTTP_RANGE_REASSEMBLY
RUST_FEATURES +=	http-range
endif

if RUST_CROSS_COMPILE 
RUST_TARGET = --target $(host_triplet)
endif

all-local:
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
		$(CARGO) build $(RELEASE) $(NIGHTLY_ARGS) \
			--features "$(RUST_FEATURES)" $(RUST_TARGET)
endif
	if test -e $(RUST_SURICATA_LIBDIR)/suricata.lib; then \
		cp $(RUST_SURICATA_LIBDIR)/suricata.lib \
			$(RUST_SURICATA_LIBDIR)/libsuricata.a; \
	fi
	$(MAKE) gen/rust-bindings.h

clean-local:
	rm -rf target
if HAVE_CBINDGEN
	rm -rf gen dist
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

if HAVE_CBINDGEN
gen/rust-bindings.h: $(RUST_SURICATA_LIB)
	rm -f gen/rust-bindings.h
	cbindgen --config $(abs_top_srcdir)/rust/cbindgen.toml \
		--quiet --output $(abs_top_builddir)/rust/gen/rust-bindings.h
else
gen/rust-bindings.h:
endif

doc:
	CARGO_HOME=$(CARGO_HOME) $(CARGO) doc --all-features --no-deps

if HAVE_CBINDGEN
dist/rust-bindings.h:
	cbindgen --config $(abs_top_srcdir)/rust/cbindgen.toml \
		--quiet --output $(abs_top_builddir)/rust/dist/rust-bindings.h
else
dist/rust-bindings.h:
endif
