.. role:: example-rule-emphasis

SCTP Keywords
=============

Suricata supports sticky buffers and keywords for matching on SCTP
packet headers, chunks, and metadata.

Sticky buffers are expected to be followed by one or more
:doc:`payload-keywords`.

sctp.hdr
--------

Sticky buffer to match on the raw SCTP header and all chunks.

Example rule:

.. container:: example-rule

    alert sctp any any -> any any (msg:"SCTP header match"; :example-rule-emphasis:`sctp.hdr; content:"|01|"; offset:8; depth:1;` sid:1; rev:1;)

``sctp.hdr`` is a 'sticky buffer'.

``sctp.hdr`` can be used as ``fast_pattern``.

sctp.data
---------

Sticky buffer to match on the SCTP DATA chunk user payload.

Example rule:

.. container:: example-rule

    alert sctp any any -> any any (msg:"SCTP DATA payload match"; :example-rule-emphasis:`sctp.data; content:"test";` sid:2; rev:1;)

``sctp.data`` is a 'sticky buffer'.

``sctp.data`` can be used as ``fast_pattern``.

sctp.vtag
---------

Match on the SCTP verification tag field in the common header.

sctp.vtag uses an :ref:`unsigned 32-bit integer <rules-integer-keywords>`.

Syntax::

 sctp.vtag:[op]<number>

The verification tag can be matched exactly, or compared using the _op_ setting::

 sctp.vtag:12345         # exactly 12345
 sctp.vtag:>0            # greater than 0
 sctp.vtag:100-200       # range 100 to 200

Example rule:

.. container:: example-rule

    alert sctp any any -> any any (msg:"SCTP vtag match"; :example-rule-emphasis:`sctp.vtag:0;` sid:3; rev:1;)

sctp.chunk_type
---------------

Match on the type of the first SCTP chunk in the packet.

sctp.chunk_type uses an :ref:`unsigned 8-bit integer <rules-integer-keywords>`.

Syntax::

 sctp.chunk_type:[op]<number>

The chunk type can be matched exactly, or compared using the _op_ setting::

 sctp.chunk_type:1       # INIT chunk (type 1)
 sctp.chunk_type:0       # DATA chunk (type 0)
 sctp.chunk_type:0-4     # range 0 to 4

Example rule:

.. container:: example-rule

    alert sctp any any -> any any (msg:"SCTP INIT chunk detected"; :example-rule-emphasis:`sctp.chunk_type:1;` sid:4; rev:1;)

sctp.chunk_cnt
--------------

Match on the number of SCTP chunks in the packet.

sctp.chunk_cnt uses an :ref:`unsigned 8-bit integer <rules-integer-keywords>`.

Syntax::

 sctp.chunk_cnt:[op]<number>

The chunk count can be matched exactly, or compared using the _op_ setting::

 sctp.chunk_cnt:1        # exactly 1 chunk
 sctp.chunk_cnt:>3       # more than 3 chunks
 sctp.chunk_cnt:2-5      # range 2 to 5

Example rule:

.. container:: example-rule

    alert sctp any any -> any any (msg:"SCTP packet with multiple chunks"; :example-rule-emphasis:`sctp.chunk_cnt:>1;` sid:5; rev:1;)

sctp.has_init
-------------

Match if the SCTP packet contains an INIT or INIT_ACK chunk. This is a
boolean keyword that takes no arguments.

Example rule:

.. container:: example-rule

    alert sctp any any -> any any (msg:"SCTP INIT or INIT_ACK detected"; :example-rule-emphasis:`sctp.has_init;` sid:6; rev:1;)

sctp.has_data
-------------

Match if the SCTP packet contains a DATA chunk. This is a boolean keyword
that takes no arguments.

Example rule:

.. container:: example-rule

    alert sctp any any -> any any (msg:"SCTP DATA chunk detected"; :example-rule-emphasis:`sctp.has_data;` sid:7; rev:1;)

sctp.has_abort
--------------

Match if the SCTP packet contains an ABORT chunk. This is a boolean keyword
that takes no arguments.

Example rule:

.. container:: example-rule

    alert sctp any any -> any any (msg:"SCTP ABORT chunk detected"; :example-rule-emphasis:`sctp.has_abort;` sid:8; rev:1;)
