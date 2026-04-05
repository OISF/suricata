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

In both cases, transforms execute before detection-time keywords such as
``byte_extract`` and ``byte_math``. The transformed buffer is what all
subsequent keywords — including ``content`` — operate on.

Variable Keys
=============

Because transforms run before detection-time variable resolution, a transform
that needs key material from the buffer must read it directly at transform time.

The ``xor`` transform supports this with the ``var <nbytes> <offset>`` syntax:
the rule author specifies the buffer position and width of the key directly.
At transform time the engine reads ``<nbytes>`` bytes starting at ``<offset>``
in the raw (pre-transform) buffer. This works at both prefilter and full
inspection because the key bytes are at a known, fixed position in the raw
buffer.

Transform Identity
==================

The engine deduplicates inspection buffers: rules that use the same buffer
keyword with the same transform configuration share one pre-computed buffer.
Equivalence is determined at rule load time by comparing an identity value
that each transform instance produces from its configuration. Instances with
identical identity share a buffer; instances with different identity (or where
a transform produces no identity) get independent buffers.

For ``xor`` with a static key the key bytes are the identity. For a variable
key the identity is the key's offset and byte count — so two rules reading
their key from the same buffer location share a buffer, while two rules with
different key locations each get their own correctly transformed buffer.
