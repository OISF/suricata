# LibHTP

---

Copyright 2009-2010 Open Information Security Foundation  
Copyright 2010-2013 Qualys, Inc.

---

LibHTP is a security-aware parser for the HTTP protocol and the related bits
and pieces. The goal of the project is mainly to support the Suricata use case.
Other use cases might not be fully supported, and we encourage you to cover these.

See the LICENSE file distributed with this work for information
regarding licensing, copying and copyright ownership.


# Usage
Start using libHTP by including it in your project's `Cargo.toml`
dependencies. The base library will also be required for using common
types.

**The minimum supported version of `rustc` is `1.58.1`.**

## Example
```
[dependencies]
htp = "2.0.0"
```

## FFI Support
LibHTP has a foreign function interface for use in C/C++ projects.
FFI Support can be enabled by building with the `cbindgen` feature.

```
# Install cbindgen which is required to generate headers
cargo install --force cbindgen

# Build headers and shared objects
make
```

## LICENSE

LibHTP is licensed under the BSD 3-Clause license (also known as "BSD New" and
"BSD Simplified".) The complete text of the license is enclosed in the file LICENSE.
