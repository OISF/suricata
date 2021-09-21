*******************************
Application Layer Frame Support
*******************************

.. contents:: Table of Contents

Baseline
========

- Basic functioning of the Suricata engine (application layer `transactions <https://github.com/OISF/suricata/blob/master/doc/devguide/extending/app-layer/transactions.rst>`_ and Suricata flows)
- `Suricata rules format <https://suricata.readthedocs.io/en/latest/rules/intro.html>`_
- It helps to understand the basics of the `Multi-pattern rule matching <https://suricata.readthedocs.io/en/latest/configuration/suricata-yaml.html?highlight=multi%20pattern%20matcher#detection-engine>`_ algorithm, used for rule filtering and to address engine performance

General Concepts
================

Frame support was introduced with Suricata-7.0. Up until 6.0x, Suricata's architecture and state of parsers meant that the network traffic stream wasn't readily available to the
detection engine. It only had access to higher level abstractions - *State* and *Transactions* (much heavier objects, that store application layer records information in the form of *Request-Response* pairs).

.. note:: For Suricata, *Frame* is a generic term that can represent any unit of network data we are interested in, which could be comprised of one or several records of other, lower level protocol(s).

The normal pipeline of detection in Suricata implied that:

- Certain rules could be quite costly performance-wise. This happened because the same stream could be inspected several times for different rules, since for certain signatures the detection is done when Suricata is still inspecting a lower level stream, not the application layer protocol (e.g., *TCP* traffic, in place of *SMB* one);
- Rules could be difficult and tedious to write (and read), requiring that writers go in byte-detail to express matching on specific payload patterns.

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

.. literalinclude:: ../../../../rust/src/smb/smb.rs
    :caption: rust/src/smb/smb.rs
    :language: rust
    :start-at: pub fn parse_tcp_data_ts<'b>
    :end-at: nbss_hdr.data, nbss_hdr.length as i64);
    :lines: 1-3, 55-74
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

- ``flow``: dedicated data type to carry specific flow-related data
- ``stream_slice``: dedicated data type to carry stream data, shown bellow
- ``frame_start``: a pointer to the start of the frame buffer in the stream, ``cur_i`` in the example code snippet
- ``frame_len``: what we expect the frame length to be (the engine may need to wait until it has enough data...)
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

