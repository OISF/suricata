EXTRA_DIST =	src derive config \
		.cargo/config.in \
		cbindgen.toml \
		include/rust-bindings.h \
		include/rust-config.h \
		vendor

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

if RUST_CROSS_COMPILE 
RUST_TARGET = --target $(host_triplet)
endif

all-local: Cargo.toml
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
		cp -a $(RUST_SURICATA_LIBDIR)/suricata.lib \
			$(RUST_SURICATA_LIBDIR)/${RUST_SURICATA_LIBNAME}; \
	fi
	if test -e $(RUST_SURICATA_LIBDIR)/libsuricata.a; then \
		cp -a $(RUST_SURICATA_LIBDIR)/libsuricata.a \
			$(RUST_SURICATA_LIBDIR)/${RUST_SURICATA_LIBNAME}; \
	fi
	$(MAKE) target/include/rust-bindings.h
	$(MAKE) target/include/rust-config.h

install-library:
	$(MKDIR_P) "$(DESTDIR)$(libdir)"
	$(INSTALL_DATA) $(RUST_SURICATA_LIB) "$(DESTDIR)$(libdir)"

uninstall-local:
	rm -f "$(DESTDIR)$(libdir)/$(RUST_SURICATA_LIBNAME)"

clean-local:
	rm -rf target

distclean-local:
	rm -f Cargo.lock

maintainer-clean-local:
	rm -rf vendor gen

check:
	CARGO_HOME="$(CARGO_HOME)" @rustup_home@ \
		CARGO_TARGET_DIR="$(abs_top_builddir)/rust/target" \
		$(CARGO) test --all $(RELEASE) --features "$(RUST_FEATURES)"

vendor:
	CARGO_HOME="$(CARGO_HOME)" @rustup_home@ $(CARGO) vendor > /dev/null

# These targets for cbindgen are used during development, to make sure that
# each call to make rebuilds the includes if the library has been updated, just
# to make sure they are current with the code.
#
# See commit e6668560e0740888b6d8a4128f092a455918ce7f for more info.
if HAVE_CBINDGEN
target/include/rust-bindings.h: $(RUST_SURICATA_LIB)
	cbindgen --config $(abs_top_srcdir)/rust/cbindgen.toml \
		--quiet --verify --output $(abs_top_builddir)/rust/$@ || true
target/include/rust-config.h: $(RUST_SURICATA_LIB)
	cbindgen --config $(abs_top_srcdir)/rust/config/cbindgen.toml \
		--quiet --verify --output $(abs_top_builddir)/rust/$@ config || true
else
target/include/rust-bindings.h:
target/include/rust-config.h:
endif

# These targets for cbindgen are used during make dist, they are the same as
# above but don't depend on the library, as building the library is not usually
# part of a "make dist", and they will be current for the code that is included
# in the distribution.
if HAVE_CBINDGEN
include/rust-bindings.h:
	cbindgen --config $(abs_top_srcdir)/rust/cbindgen.toml \
		--quiet --output $(abs_top_builddir)/rust/$@
include/rust-config.h:
	cbindgen --config $(abs_top_srcdir)/rust/config/cbindgen.toml \
		--quiet --output $(abs_top_builddir)/rust/$@ config
else
include/rust-bindings.h:
include/rust-config.h:
endif

doc:
	CARGO_HOME=$(CARGO_HOME) $(CARGO) doc --all-features --no-deps
