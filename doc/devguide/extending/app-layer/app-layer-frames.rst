*******************************
Application Layer Frame Support
*******************************

.. contents:: Table of Contents

Baseline
========

- `Suricata rules format <https://suricata.readthedocs.io/en/latest/rules/intro.html>`_
- It helps to understand the basics of the `Multi-pattern rule matching <https://suricata.readthedocs.io/en/latest/configuration/suricata-yaml.html?highlight=multi%20pattern%20matcher#detection-engine>`_ algorithm, used for rule filtering and to address engine performance

General Concepts
================

Frame support was introduced with Suricata-7.0. Up until 6.0x, Suricata's architecture and state of parsers meant that the network traffic available to the detection engine was just a stream of data, without detail about higher level parsers. 

.. note:: For Suricata, *Frame* is a generic term that can represent any unit of network data we are interested in, which could be comprised of one or several records of other, lower level protocol(s). Frames work as "stream annotations", allowing Suricata to tell the detection engine what type of record exists at a specific offset in the stream.

The normal pipeline of detection in Suricata implied that:

- Certain rules could be quite costly performance-wise. This happened because the same stream could be inspected several times for different rules, since for certain signatures the detection is done when Suricata is still inspecting a lower level stream, not the application layer protocol (e.g., *TCP* traffic, in place of *SMB* one);
- Rules could be difficult and tedious to write (and read), requiring that writers went in byte-detail to express matching on specific payload patterns.

What the Frame support offers is the ability to "point" to a specific portion of stream and identify what type of traffic Suricata is looking at. Then, as the engine reassembles the stream, one can have "read access" to that portion of the stream, aggregating concepts like what type of application layer protocol that is, and differentiating between ``header``, ``data`` or even protocol versions (*SMB1*, *SMB2*...).

The goal of the stream *Frame* is to expose application layer protocol `PDUs <https://en.wikipedia.org/wiki/Protocol_data_unit>`_ and other such arbitrary elements to the detection engine directly, instead of relying on Transactions. The main purpose is to bring *TCP.data* processing times down by specialising/ filtering down traffic detection.

Adding Frame Support to a Parser
================================

The application layer parser exposes frames it supports to the detect engine, by tagging them as they're parsed. The rest works automatically.

In order to allow the engine to identify frames for records of a given application layer parser, thought must be given as to which frames make sense for the specific protocol you are handling. Some parsers may have clear ``header`` and ``data`` fields that form its *protocol data unit* (pdu). For others, the distinction might be between ``request`` and ``response``, only. Whereas for others it may make sense to have specific types of data. This is better understood by seeing the different types of frame keywords, which vary on a per-protocol basis. 

It is also important to keep follow naming conventions when defining Frame Types. While a protocol may strong naming standards for certain structures, do compare those with what Suricata already has registered:

- ``hdr``: used for the record header portion
- ``data``: is used for the record data portion
- ``pdu``: unless documented otherwise, means the whole record, comprising ``hdr`` and ``data``
- ``request``: a message from a client to a server
- ``response``: a message from a server to a client

Once that is settled, the basic steps are:

- create an enum with the frame types;
- identify the parsing function(s) where application layer records are parsed;
- identify the correct moment to register the frames (when the input stream is being parsed into records);
- use the Frame API calls directly or build upon them and use your functions to register the frames;
- register the relevant frame callbacks when registering the parser.

Once these are done, you can enable frame eve-output to confirm that your frames are being properly registered. It is important to notice that some hard coded limits could influence what you see on the logs (max size of log output; type of logging for the payload, cf. https://redmine.openinfosecfoundation.org/issues/4988).

If all the steps are successfully followed, you should be able to write a rule using the *frame* keyword and the frame types you have registered with the application layer parser.

Using the *SMB* parser as example, before frame support, a rule would look like::

    alert tcp ... flow:to_server; content:"|ff|SMB"; content:"some smb 1 issue";

With frame support, one is able to do::

    alert smb ... flow:to_server; frame:smb1.data; content:"some smb 1 issue";

Implementation & API Callbacks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Rust
----

The frame types are defined as an enum. In Rust, derive from the ``AppLayerFrameType``:

.. literalinclude:: ../../../../rust/src/smb/smb.rs
    :caption: rust/src/smb/smb.rs
    :language: rust
    :start-at: #[derive(AppLayerFrameType)]
    :lines: 1-15

How some frames are registered in the `SMB <https://github.com/OISF/suricata/blob/master/rust/src/smb/smb.rs#L1383>`_ parser:

.. literalinclude:: ../../../../rust/src/smb/smb.rs
    :caption: rust/src/smb/smb.rs
    :language: rust
    :start-at: pub fn parse_tcp_data_ts<'b>
    :end-at: nbss_hdr.data, nbss_hdr.length as i64);
    :lines: 1-3, 56-74
    :dedent: 4

These are the frame registration functions highlighted above:

.. literalinclude:: ../../../../rust/src/smb/smb.rs
    :caption: rust/src/smb/smb.rs
    :language: rust
    :start-at: fn add_nbss_ts_frames(&mut
    :end-before: fn add_smb1_ts_hdr_data
    :dedent: 4

Frame registering with the `telnet <https://github.com/OISF/suricata/blob/master/rust/src/telnet/telnet.rs#L171>`_ parser:

.. _telnet-snippet:

.. literalinclude:: ../../../../rust/src/telnet/telnet.rs
    :caption: rust/src/telnet/telnet.rs
    :language: rust
    :start-at: fn parse_request
    :end-at: TelnetFrameType::Data as u8)
    :lines: 1, 19-29
    :dedent: 4

The parameters represent:

- ``flow``: dedicated data type, carries specific flow-related data
- ``stream_slice``: dedicated data type, carries stream data, shown further bellow
- ``frame_start``: a pointer to the start of the frame buffer in the stream (``cur_i`` in the SMB code snippet)
- ``frame_len``: what we expect the frame length to be (the engine may need to wait until it has enough data. See what is done in the telnet snippet request frames registering)
- ``frame_type``: type of frame it's being registering (defined in an enum, as shown further above)

.. note:: on frame_len
        
    For protocols which search for an end of frame char, like telnet, indicate unknown length by passing ``-1``. Once the length is known, it must be updated. For those where length is a field in the record (e.g. *SMB*), the frame is set to match said length, even if that is bigger than the current input

``StreamSlice`` contains the input data to the parser, alongside other Stream-related data important in parsing context. Definition  is found in *applayer.rs*:

.. literalinclude:: ../../../../rust/src/applayer.rs
    :caption: rust/src/applayer.rs
    :language: rust
    :start-at: pub struct StreamSlice
    :end-before: impl StreamSlice

Registering relevant frame callbacks:

.. literalinclude:: ../../../../rust/src/smb/smb.rs
   :caption: rust/src/smb/smb.rs
   :language: rust
   :start-at: get_frame_id_by_name
   :end-at: ffi_name_from_id),
   :dedent: 8

Frame registering with the `telnet <https://github.com/OISF/suricata/blob/master/rust/src/telnet/telnet.rs#L171>`_ parser, when length is not known yet:

.. literalinclude:: ../../../../rust/src/telnet/telnet.rs
    :caption: rust/src/telnet/telnet.rs
    :language: rust
    :start-at: fn parse_request
    :end-at: TelnetFrameType::Data as u8)
    :lines: 1, 19-29
    :dedent: 4

We then update length later on (note especially lines 3 and 8):

.. literalinclude:: ../../../../rust/src/telnet/telnet.rs
    :caption: rust/src/telnet/telnet.rs
    :language: rust
    :start-at: match parser::parse_message(start)
    :end-at: frame.set_len(flow, 0, consumed as i64);
    :linenos:
    :dedent: 12

C code
------

Implementing Frame support in C involves a bit more manual work, as one cannot make use of the Rust derives. Code snippets from the *HTTP* parser:

Defining the frame types with the enum means:

.. literalinclude:: ../../../../src/app-layer-htp.c
    :caption: src/app-layer-htlp.c
    :start-at: enum HttpFrameTypes
    :end-before: static int HTTPGetFrameId
    :lines: 1-16

The HTTP parser uses the Frame registration functions from the C API (``app-layer-frames.c``) directly for registering request Frames. Here we also don't know the length yet. The ``0`` indicates flow direction: ``toserver``, and ``1`` would be used for ``toclient``:

.. literalinclude:: ../../../../src/app-layer-htp.c
    :caption: src/app-layer-htlp.c
    :start-after: (uint64_t)hstate->conn->in_data_counter);
    :end-before: if (hstate->cfg)
    :lines: 2-8
    :linenos:
    :dedent: 4

Updating ``frame->len`` later:

.. literalinclude:: ../../../../src/app-layer-htp.c
    :caption: src/app-layer-htlp.c
    :start-at: if (hstate->request_frame_id > 0) {
    :end-before: hstate->request_frame_id = 0;
    :dedent: 4

Register relevant callbacks:

.. literalinclude:: ../../../../src/app-layer-htp.c
    :caption: src/app-layer-htp.c
    :language: c
    :start-at: AppLayerParserRegisterGetFrameFuncs
    :end-at: FrameNameById);


Visual context
==============

``input`` and ``input_len`` are used to calculate the proper offset, for storing the frame. The stream buffer slides forward, so frame offsets/frames have to be updated. The `relative offset` (``rel_offset``) reflects that:

.. code-block:: c

    Start:
    [ stream ]
      [ frame   ...........]
       rel_offset: 2
       len: 19

    Slide:
         [ stream ]
    [ frame ....          .]
     rel_offset: -10
     len: 19

    Slide:
                [ stream ]
    [ frame ...........    ]
     rel_offset: -16
     len: 19

The way the engine handles stream frames can be illustrated as follows:

.. image:: img/StreamFrames.png
   :scale: 80

