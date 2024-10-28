EXTRA_DIST =	src derive \
		.cargo/config.toml.in \
		cbindgen.toml \
		dist/rust-bindings.h \
		vendor \
		Cargo.toml Cargo.lock \
		derive/Cargo.toml

if !DEBUG
RELEASE = --release
endif

if RUST_BUILD_STD
NIGHTLY_ARGS = -Z build-std
endif

if HAVE_JA3
RUST_FEATURES +=	ja3
endif

if HAVE_JA4
RUST_FEATURES +=	ja4
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

if HAVE_CYGPATH
CARGO_ENV =	@rustup_home@ \
		CARGO_HOME="$(CARGO_HOME)" \
		CARGO_TARGET_DIR="$(e_rustdir)/target" \
		SURICATA_LUA_SYS_HEADER_DST="$(e_rustdir)/gen" \
		TOP_BUILDDIR=$(abs_top_builddir) \
		TOP_SRCDIR=$(abs_top_srcdir) \
		RUST_GENDIR=$(e_rustdir)/gen
else
CARGO_ENV =	@rustup_home@ \
		CARGO_HOME="$(CARGO_HOME)" \
		CARGO_TARGET_DIR="$(abs_top_builddir)/rust/target" \
		SURICATA_LUA_SYS_HEADER_DST="$(abs_top_builddir)/rust/gen" \
		TOP_BUILDDIR=$(abs_top_builddir) \
		TOP_SRCDIR=$(abs_top_srcdir) \
		RUST_GENDIR=$(abs_top_builddir)/rust/gen
endif

all-local: Cargo.toml
	mkdir -p $(abs_top_builddir)/rust/gen
	cd $(abs_top_srcdir)/rust && \
		$(CARGO_ENV) \
		$(CARGO) build $(RELEASE) $(NIGHTLY_ARGS) \
			--features "$(RUST_FEATURES)" $(RUST_TARGET)
	if test -e $(RUST_SURICATA_LIBDIR)/suricata.lib; then \
		cp -a $(RUST_SURICATA_LIBDIR)/suricata.lib \
			$(RUST_SURICATA_LIBDIR)/${RUST_SURICATA_LIBNAME}; \
	fi
	if test -e $(RUST_SURICATA_LIBDIR)/libsuricata.a; then \
		cp -a $(RUST_SURICATA_LIBDIR)/libsuricata.a \
			$(RUST_SURICATA_LIBDIR)/${RUST_SURICATA_LIBNAME}; \
	fi
	$(MAKE) gen/rust-bindings.h

install-library:
	$(MKDIR_P) "$(DESTDIR)$(libdir)"
	$(INSTALL_DATA) $(RUST_SURICATA_LIB) "$(DESTDIR)$(libdir)"

uninstall-local:
	rm -f "$(DESTDIR)$(libdir)/$(RUST_SURICATA_LIBNAME)"

clean-local:
	rm -rf target gen

distclean-local:
	rm -rf vendor dist

check:
	cd $(abs_top_srcdir)/rust && \
		$(CARGO_ENV) \
		$(CARGO) test --all $(RELEASE) --features "$(RUST_FEATURES)"

vendor:
	$(CARGO_ENV) $(CARGO) vendor

update-bindings:
if HAVE_BINDGEN
	$(BINDGEN) \
		-o src/_sys.rs \
		--disable-header-comment \
		--allowlist-type 'SCAppLayerEventType' \
		--rustified-enum 'SCAppLayerEventType' \
		$(abs_top_srcdir)/src/bindgen.h \
		-- \
		-DHAVE_CONFIG_H -I../src $(CPPFLAGS)
else
	@echo "error: bindgen not installed, can't update bindings"
	exit 1
endif

if HAVE_CBINDGEN
gen/rust-bindings.h: $(RUST_SURICATA_LIB)
	cd $(abs_top_srcdir)/rust && \
		cbindgen --config $(abs_top_srcdir)/rust/cbindgen.toml \
		--quiet --verify --output $(abs_top_builddir)/rust/gen/rust-bindings.h || true
else
gen/rust-bindings.h:
endif

doc:
	CARGO_HOME=$(CARGO_HOME) \
		$(CARGO_ENV) \
		SURICATA_LUA_SYS_HEADER_DST="" $(CARGO) doc \
		--all-features --no-deps

if HAVE_CBINDGEN
dist/rust-bindings.h:
	cbindgen --config $(abs_top_srcdir)/rust/cbindgen.toml \
		--quiet --output $(abs_top_builddir)/rust/dist/rust-bindings.h
else
dist/rust-bindings.h:
endif

Cargo.toml: Cargo.toml.in

update-lock: Cargo.toml
	cargo update
	mv Cargo.lock Cargo.lock.in
