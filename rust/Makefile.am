EXTRA_DIST = 	Cargo.toml \
		src \
		.cargo/config.in

if HAVE_RUST

EXTRA_DIST +=	Cargo.lock

if HAVE_CARGO_VENDOR
EXTRA_DIST +=	vendor
endif

if HAVE_RUST_VENDOR
FROZEN = --frozen
endif

if !HAVE_RUST_HEADERS
EXTRA_DIST += gen 
EXTRA_DIST += cbindgen.toml
endif

if !DEBUG
RELEASE = --release
endif

if HAVE_LUA
RUST_FEATURES +=	lua
endif

if DEBUG
RUST_FEATURES +=	debug
endif

build-rust:
	cd $(top_srcdir)/rust

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

if HAVE_RUST_HEADERS

all-local: build-rust
	echo Rust headers available

clean-local:
	-rm -rf target

distclean-local: clean-local
	rm -rf vendor Cargo.lock

else 

all-local: gen build-rust
	echo Generating rust headers

clean-local:
	-rm -rf target gen

distclean-local: clean-local
	rm -rf vendor gen Cargo.lock

endif

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

if !HAVE_RUST_HEADERS
gen: FORCE
	cbindgen --config cbindgen.toml --output "gen/rust-bindings.h" > /dev/null
FORCE:
else
gen:
endif

else # HAVE_RUST

all-local clean-local check vendor gen:

endif # HAVE_RUST
