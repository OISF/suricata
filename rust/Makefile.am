EXTRA_DIST = Cargo.toml Cargo.lock \
		src \
		.cargo/config.in \
                gen \
                cbindgen.toml

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

build-rust:
	cd $(top_srcdir)/rust

if HAVE_CYGPATH
	rustpath=`cygpath -a -t mixed $(abs_top_builddir)`
	cd $(top_srcdir)/rust && @rustup_home@ \
		CARGO_HOME="$(CARGO_HOME)" \
		CARGO_TARGET_DIR="$$rustpath/rust/target" \
		$(CARGO) build $(RELEASE) $(FROZEN) \
			--features "$(RUST_FEATURES)"
else
	cd $(top_srcdir)/rust && @rustup_home@ \
		CARGO_HOME="$(CARGO_HOME)" \
		CARGO_TARGET_DIR="$(abs_top_builddir)/rust/target" \
		$(CARGO) build $(RELEASE) $(FROZEN) \
			--features "$(RUST_FEATURES)"
endif

if HAVE_RUST_HEADERS

all-local: build-rust
	$(info Rust headers available)

clean-local:
	-rm -rf target

distclean-local: clean-local
	rm -rf vendor Cargo.lock

else 

all-local: gen-headers build-rust
	$(info Generating rust headers)

clean-local:
	-rm -rf target gen

distclean-local: clean-local
	rm -rf vendor gen Cargo.lock

endif

check:
	CARGO_HOME="$(CARGO_HOME)" @rustup_home@
		$(CARGO) test --features "$(RUST_FEATURES)"

Cargo.lock: Cargo.toml
	CARGO_HOME="$(CARGO_HOME)" @rustup_home@ $(CARGO) \
		generate-lockfile

if HAVE_CARGO_VENDOR
vendor:
	CARGO_HOME="$(CARGO_HOME)" @rustup_home@ $(CARGO) vendor > /dev/null
else
vendor:
endif

gen-headers: FORCE
	cbindgen --config cbindgen.toml --output "gen/rust-bindings.h" > /dev/null
FORCE:
