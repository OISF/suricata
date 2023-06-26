# LibHTP

---

Copyright 2009-2010 Open Information Security Foundation  
Copyright 2010-2013 Qualys, Inc.

---

LibHTP is a security-aware parser for the HTTP protocol and the related bits
and pieces. The goals of the project, in the order of importance, are as
follows:

 1. Completeness of coverage; LibHTP must be able to parse virtually all
    traffic that is found in practice.

 2. Permissive parsing; LibHTP must never fail to parse a stream that would
    be parsed by some other web server.

 3. Awareness of evasion techniques; LibHTP must be able to detect and
    effectively deal with various evasion techniques, producing, where
    practical, identical or practically identical results as the web
    server processing the same traffic stream.

 4. Performance; The performance must be adequate for the desired tasks.
    Completeness and security are often detrimental to performance. Our
    idea of handling the conflicting requirements is to put the library
    user in control, allowing him to choose the most desired library
    characteristic.

 | IMPORTANT   LIBHTP IS NOT YET CONSIDERED STABLE. USE AT YOUR OWN RISK. DO NOT  
 |             USE IN PRODUCTION. WORK IS CURRENTLY UNDER WAY TO ENSURE THAT  
 |             LIBHTP IS SECURE AND THAT IT PERFORMS WELL.  

 | STATUS      LIBHTP IS VERY YOUNG AT THIS POINT. IT WILL BE SOME TIME BEFORE  
 |             IT CAN BE CONSIDER COMPLETE. AT THE MOMENT, THE FOCUS OF DEVELOPMENT  
 |             IS ON ACHIEVING THE FIRST TWO GOALS.  

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
