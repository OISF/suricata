***********************************************
Application Layer Frame Support - Stream Slice 
***********************************************

.. contents:: Table of Contents

Baseline
========

- `Multi-pattern rule matching <https://suricata.readthedocs.io/en/latest/configuration/suricata-yaml.html?highlight=multi%20pattern%20matcher#detection-engine>`_ algorithm, used for rule filtering and address engine performance
- Basic functioning of the Suricata engine, like application layer `transactions <https://github.com/OISF/suricata/blob/master/doc/devguide/extending/app-layer/transactions.rst>`_ and Suricata flows.

Scope
=====

- What is Application Layer Frame Support
  -Advantages
- What are Stream Slices
- How do Stream Slices work
- Implementation Details
- Examples
- Adding support to existing parsers

General Concepts
================

.. note:: Stream Frames support is a work in progress. This means that names and some implementation details might still change, before we reach a more stable version of the code. The overall idea behind it is matured, though, so this documentation is still valid. Current progress: `Feat/appl records <https://github.com/OISF/suricata/pull/6684>`_

Suricata's architecture and current state of parsers mean that the network traffic stream isn't readily available to the
detection engine. Except for the application layer parsers, the Suricata engine only has access to higher level
abstractions - *State* and *Transactions* (much heavier objects, that store `Frame` information in the form of *Request-Response* pairs).

The goal of the stream `Frames` is to expose application layer protocol PDUs and other arbitrary records to the detection engine directly, instead of relying on Transactions. The main purpose is to bring `TCP.data` processing times down, by specialising/ filtering down traffic detection.

The normal pipeline of detection in Suricata implies at least two things:

- Certain rules can be quite costly performance-wise. This happens because the same stream could be inspected several times for different rules, because for certain signatures the detection is done when Suricata is still inspecting a lower level stream, not the application layer protocol (e.g., `TCP` traffic, in place of `SMB` one);
- Rules can be difficult and tedious to write (and read), requiring that the writer go in byte-detail to express matching on specific payload patterns.

For example, if they were to write a rule for SMB to match on content "vigilant meerkat", they will have to do something like::

    alert tcp any any -> any any (content:"|ff|SMB"; offset:4; depth:4;
    \content:"vigilant meerkat"; sid:1; rev:1;)

For a rule like the above, even though one is interested in `SMB` traffic only, Suricata will inspect *all* `TCP` traffic `toserver` - regardless of application layer protocols.

What the Stream Frames offer is the ability to "point" to a specific portion of stream and identify what type of traffic Suricata is looking at, allowing for the previous example rule to become something like::

    alert smb any any -> any any (record:smb.smb1.data; content:"vigilant meerkat"; sid:1; rev:1;)

As the engine reassembles the stream, the stream frame support allows one to have "read access" to that portion of the stream, aggregating concepts like: what type of application layer protocol that is, and differentiating between `header`, `data` or even protocol versions (`SMB1`, `SMB2`...).

As the example rule shows, this allows for easier to write, more human-readable rules, with the benefit that they are also less costly for the engine to inspect.

Rule Writing
============

An advantage of this feature is that there is a single rule keyword for the frame record: ``record``.
This keyword takes an argument to specify the per protocol record type::

    record:<app proto name>.<specific record name>

Examples::

    tls.pdu
    tls.hdr
    smb.smb2.smb2.hdr
    smb.smb3.data

Rules will look something like this::

    alert tls any any -> any any (flow:to_server; record:tls.pdu; \
         content:"|16 03|"; startswith; sid:1;)
    alert tls any any -> any any (flow:to_server; record:tls.hdr; \
         content:"|16 03|"; startswith; sid:2;)
    alert tls any any -> any any (flow:to_server; record:tls.data; \
         content:"|aa aa aa aa|"; startswith; sid:3;)
    alert smb any any -> any any (flow:to_server; record:smb.nbss.pdu; \
         content:"|fe|SMB"; offset:4; depth:4; sid:25;)
    alert smb any any -> any any (flow:to_client; record:smb.nbss.pdu; \
         content:"|fe|SMB"; offset:4; depth:4; sid:26;)
    alert smb any any -> any any (flow:to_server; record:smb.smb1.pdu; content:"|ff|SMB"; sid:21;)


Implementation & API Callbacks
==============================

The application layer parser exposes records it supports to the detect engine, by tagging them as they're parsed. The rest works automatically.

A code example from the `SMB` decoder (`rust/src/smb/smb.rs`) - code excerpt from `PR #6684 <https://github.com/OISF/suricata/pull/6684/commits/2921c6c81f2ab72adbab146670810dc6d869db52>`_:

    .. code-block:: rust

         pub fn parse_tcp_data_ts<'b>(&mut self, flow: *const Flow, stream_slice: &StreamSlice) 
         -> AppLayerResult
         {
            let mut cur_i = stream_slice.as_slice(); // pointer to current input
               .
               while cur_i.len() > 0 {
                 match parse_nbss_record(cur_i) {
                 .
                 .
                   let (_nbss_pdu, _nbss_pdu_id) = applayer_new_frame_ts(flow, stream_slice, cur_i,
                           nbss_hdr.length as i32 + 4, SMBFrameType::NBSS as u8);
                   let (_nbss_hdr_frame, _nbss_frame_id) = applayer_new_frame_ts(flow, stream_slice, 
                           cur_i, 4, SMBFrameType::NBSSHdr as u8);
                   let (_nbss_data_frame, _nbss_data_frame_id) = applayer_new_frame_ts(flow, 
                           stream_slice, &cur_i[4..], nbss_hdr.length as i32, SMBFrameType::NBSSData as u8);
                 .
                 .
                 }
            }
         }

There are a number of possible function calls for registering the `frames`. These are avaialable from `applayer.rs`

A frame to the server can be registered like so:

.. code-block:: rust

    pub fn applayer_new_frame_ts(
            flow: *const Flow,
            stream_slice: &StreamSlice, 
            frame_start: &[u8], 
            frame_len: i32, 
            frame_type: u8) -> (*const Frame, i64)
    {
        applayer_new_frame_with_dir(flow, stream_slice, frame_start, frame_len, 0, frame_type)
    }

The parameters represent:

- ``flow``: dedicated data type to carry specific flow-related data
- ``stream_slice``: dedicated data type to carry stream data, shown bellow
- ``frame_start``: a pointer to the start of the frame buffer in the stream, ``cur_i`` in the example code snippet
- ``frame_len``: what we expect the record length to be (the engine may need to wait until it has enough data...)
- ``frame_type``: type of frame we're registering (in the examples we have `NBSS Header` and `NBSSData`, for instance).

The representation of the StreamSlice is found at rust/src/applayer.rs:

.. code-block:: rust

    pub struct StreamSlice {
         input: *const u8,
         input_len: u32,
         /// STREAM_* flags
         flags: u8,
         offset: u64,
    }


More context
------------

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

The frame support/ stream slice record workings can be illustrated as follows:

.. image:: img/StreamFrames.png
   :width: 800

Adding Frame Support to a Parser
================================

To add this feature to a parser:

- identify the parsing function(s) where application layer records are parsed;
- choose from the Frame API calls the one that makes more sense for the given case;
- identify the correct moment to use the calls;
- add frame logging (output) capability, if you want Suricata to be able to add a Frame event type to EVE logs.
