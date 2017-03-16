EXTRA_DIST = 	Cargo.toml \
		src/lib.rs

if HAVE_RUST
all-local:
# If building in an alternate directory, Cargo.toml gets linked in by
# AC_CONFIG_LINKS, but that doesn't support directories. So instead of
# linking everything file under src, just link in the src directory
# here.
	if ! test -e src; then \
		ln -s $(top_srcdir)/rust/src .; \
	fi
if DEBUG
	cargo build
else
	cargo build --release
endif

clean-local:
	cargo clean
	rm -f Cargo.lock

check:
	cargo test
else
all-local clean-local check:
endif

