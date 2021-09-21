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

What the Frame support offers is the ability to "point" to a specific portion of stream and identify what type of traffic Suricata is looking at.Then, as the engine reassembles the stream, one can have "read access" to that portion of the stream, aggregating concepts like what type of application layer protocol that is, and differentiating between ``header``, ``data`` or even protocol versions (*SMB1*, *SMB2*...).

The goal of the stream *Frame* is to expose application layer protocol `PDUs <https://en.wikipedia.org/wiki/Protocol_data_unit>`_ and other such arbitrary elements to the detection engine directly, instead of relying on Transactions. The main purpose is to bring *TCP.data* processing times down by specialising/ filtering down traffic detection.

Adding Frame Support to a Parser
================================

The application layer parser exposes frames it supports to the detect engine, by tagging them as they're parsed. The rest works automatically.

In order to allow the engine to identify frames for records of a given application layer parser, you'll have to decide which frames make sense for the specific protocol you are handling. Once you have that, the basic steps are:

- create an enum for the frame types;
- identify the parsing function(s) where application layer records are parsed;
- identify the correct moment to use the calls;
- use the Frame API calls directly or build upon them to register the frames.

Once this is done, you can enable frame eve-output to confirm that your frames are being registered correctly. If done correctly, you should be able to write a rule using the *frame* keyword and the frame type you have registered with the application layer parser.

Implementation & API Callbacks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The frame types are defined as an enum. In Rust, derive from the ``AppLayerFrameType``:

.. literalinclude:: ../../../../rust/src/smb/smb.rs
    :caption: rust/src/smb/smb.rs
    :language: rust
    :start-at: #[derive(AppLayerFrameType)]
    :lines: 1-15

How some frames are registered in the `SMB <https://github.com/OISF/suricata/blob/master/rust/src/smb/smb.rs#L1383>`_ parser:

.. _smb-snippet:

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

The function calls for registering ``frames`` are available from *frames.rs*. A frame to the server could be registered like so:

.. literalinclude:: ../../../../rust/src/frames.rs
    :caption: rust/src/frames.rs
    :language: rust
    :start-at: pub fn new_ts
    :end-before: pub fn new_tc
    :dedent: 4

And to the client:

.. literalinclude:: ../../../../rust/src/frames.rs
    :caption: rust/src/frames.rs
    :language: rust
    :start-at: pub fn new_tc
    :lines: 1-6
    :dedent: 4

The parameters represent:

- ``flow``: dedicated data type, carries specific flow-related data
- ``stream_slice``: dedicated data type, carries stream data, shown bellow
- ``frame_start``: a pointer to the start of the frame buffer in the stream (``cur_i`` in the SMB code snippet)
- ``frame_len``: what we expect the frame length to be (the engine may need to wait until it has enough data. See what is done in the telnet snippet request frames registering)
- ``frame_type``: type of frame it's being registering (defined in the enum)

``StreamSlice`` contains the input data to the parser, alongside other Stream-related data important in parsing context. Definition  is found in *applayer.rs*:

.. literalinclude:: ../../../../rust/src/applayer.rs
    :caption: rust/src/applayer.rs
    :language: rust
    :start-at: pub struct StreamSlice
    :end-before: impl StreamSlice

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

