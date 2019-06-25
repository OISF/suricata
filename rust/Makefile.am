EXTRA_DIST =	src \
		.cargo/config.in \
                gen \
                cbindgen.toml

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

if RUST_CROSS_COMPILE 
RUST_TARGET = --target $(host_triplet)
endif

build-rust:
	cd $(top_srcdir)/rust

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

if HAVE_RUST_HEADERS

all-local: build-rust
	echo Rust headers available

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
	CARGO_HOME="$(CARGO_HOME)" @rustup_home@ \
		CARGO_TARGET_DIR="$(abs_top_builddir)/rust/target" \
		$(CARGO) test $(RELEASE) --features "$(RUST_FEATURES)"

if HAVE_CARGO_VENDOR
vendor:
	CARGO_HOME="$(CARGO_HOME)" @rustup_home@ $(CARGO) vendor > /dev/null
else
vendor:
endif

gen-headers: FORCE
	cbindgen --config cbindgen.toml --output "gen/rust-bindings.h" > /dev/null
FORCE:
