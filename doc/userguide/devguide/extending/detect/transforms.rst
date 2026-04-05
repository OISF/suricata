Transforms
**********

Overview
========

Transforms modify the contents of an inspection buffer before content
keywords inspect it. They are applied in the order they appear in the rule,
with each transform's output becoming the next transform's input.

Execution Order
===============

Transforms run at two points in the detection pipeline:

1. **Prefilter (MPM):** when the buffer is set up for the multi-pattern
   matcher. The MPM searches the *transformed* buffer for fast-pattern
   content.
2. **Full inspection:** when the rule's keywords are evaluated against the
   (transformed) buffer.

In both cases, transforms execute *before* ``byte_extract`` and other
match-time keywords have populated their variables. The transformed buffer
is what all subsequent keywords — including ``content`` and ``byte_extract``
— operate on.

Implications for Variable Keys
===============================

Because ``byte_extract`` runs after transforms, a transform that requires a
value from a ``byte_extract`` variable cannot read it from ``byte_values`` at
transform time — the value is not yet available.

The ``xor`` transform handles this by reading key bytes directly from the raw
(pre-transform) inspection buffer at the ``byte_extract`` variable's
*configured* offset and length (resolved at rule load time). This is why
``xor`` with a variable key only supports ``byte_extract`` variables with
absolute offsets on the same buffer: relative offsets depend on a prior
content match position that does not exist at transform time.

This approach works correctly for both prefilter and full inspection because
the key bytes are always present in the raw buffer at a known, fixed position.
