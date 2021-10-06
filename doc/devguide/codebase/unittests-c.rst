Unittests
=========

Unittests are a great way to create tests that can check the internal state
of parsers, structures and other objects.

Tests should:

- use FAIL/PASS macros
- be deterministic
- not leak memory on PASS
- not use conditions
