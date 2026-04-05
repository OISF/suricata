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
value from a ``byte_extract`` variable cannot use that variable's extracted
value at transform time — the variable has not yet been evaluated.

The ``xor`` transform handles this by reading key bytes directly from the raw
(pre-transform) inspection buffer at the ``byte_extract`` variable's
*configured* offset and length (resolved at rule load time). This is why
``xor`` with a variable key only supports ``byte_extract`` variables with
absolute offsets on the same buffer: relative offsets depend on a prior
content match position that does not exist at transform time.

This approach works correctly for both prefilter and full inspection because
the key bytes are always present in the raw buffer at a known, fixed position.

Transform Identity
==================

The engine deduplicates inspection buffers: rules that use the same buffer
keyword with the same transform configuration share one pre-computed buffer.
Equivalence is determined at rule load time by comparing an identity value
that each transform instance produces from its configuration. Instances with
identical identity share a buffer; instances with different identity (or where
a transform produces no identity) get independent buffers.

For ``xor`` with a static key the key bytes are the identity. For a variable
key the identity is the ``byte_extract`` variable's absolute offset and byte
count — so two rules reading their key from the same location share a buffer,
while two rules with different key locations each get their own correctly
transformed buffer.
