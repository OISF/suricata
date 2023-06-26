EXTRA_DIST =	src derive libhtp-rs \
		.cargo/config.toml.in \
		cbindgen.toml \
		dist/rust-bindings.h \
		dist/htp/htp_rs.h \
		vendor \
		Cargo.toml Cargo.lock \
		derive/Cargo.toml \
		libhtp-rs/Cargo.toml

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

all-local: Cargo.toml
if HAVE_CYGPATH
	cd $(abs_top_srcdir)/rust && \
		@rustup_home@ CARGO_HOME="$(CARGO_HOME)" \
		CARGO_TARGET_DIR="$(e_rustdir)/target" \
		$(CARGO) build $(RELEASE) \
			--features "$(RUST_FEATURES)" $(RUST_TARGET)
else
	cd $(abs_top_srcdir)/rust && \
		@rustup_home@ CARGO_HOME="$(CARGO_HOME)" \
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
	$(MAKE) gen/rust-bindings.h
	$(MAKE) gen/htp/htp_rs.h
	mkdir -p $(abs_top_builddir)/rust/gen
	cp -a $(RUST_SURICATA_LIBDIR)/build/suricata-lua-sys-*/out/lua/*.h \
		$(abs_top_builddir)/rust/gen/

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
		CARGO_HOME="$(CARGO_HOME)" @rustup_home@ \
		CARGO_TARGET_DIR="$(abs_top_builddir)/rust/target" \
		$(CARGO) test --all $(RELEASE) --features "$(RUST_FEATURES)"

vendor:
	CARGO_HOME="$(CARGO_HOME)" @rustup_home@ $(CARGO) vendor

if HAVE_CBINDGEN
gen/rust-bindings.h: $(RUST_SURICATA_LIB)
	cd $(abs_top_srcdir)/rust && \
		cbindgen --config $(abs_top_srcdir)/rust/cbindgen.toml \
		--quiet --verify --output $(abs_top_builddir)/rust/gen/rust-bindings.h || true
else
gen/rust-bindings.h:
endif

if HAVE_CBINDGEN
gen/htp/htp_rs.h: $(RUST_SURICATA_LIB)
	cd $(abs_top_srcdir)/rust/libhtp-rs && \
		cbindgen --config $(abs_top_srcdir)/rust/libhtp-rs/cbindgen.toml \
		--quiet --verify --output $(abs_top_builddir)/rust/gen/htp/htp_rs.h || true
else
gen/htp/htp_rs.h:
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

if HAVE_CBINDGEN
dist/htp/htp_rs.h:
	cbindgen --config $(abs_top_srcdir)/rust/libhtp-rs/cbindgen.toml \
		--quiet --output $(abs_top_builddir)/rust/gen/htp/htp_rs.h
else
dist/htp/htp_rs.h:
endif

Cargo.toml: Cargo.toml.in

update-lock: Cargo.toml
	cargo update
	mv Cargo.lock Cargo.lock.in
