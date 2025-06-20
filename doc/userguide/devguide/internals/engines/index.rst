Engines
=======

Flow
----

Stream
------

.. toctree::
   :maxdepth: 2

   stream/inspection_raw_data

Defrag
------

.. _Protocol detection:

Protocol detection
------------------

For each flow, Suricata will try to recognize the application layer protocol.

Protocol detection is run for TCP and UDP flows.
Protocol detection is run (generally) independently for both directions of the flow.
A flow can change its app-layer protocol during its lifetime (TLS upgrade for example).
Protocol detection can, in the midstream case, reverse a flow direction.
(If the first packet we see is a DNS over UDP response for example.)

Decision process
~~~~~~~~~~~~~~~~

For each flow+direction, Suricata tries the following:

1. Multi pattern matching (port-independent)

Each app-layer protocol may register a set of patterns for each direction.
(for example ``HTTP/1.`` for HTTP1 responses.)

As this is done by multi-pattern matching, this method scales, meaning
that its CPU time cost is O(1) relative to the number of protocols and patterns.
This is why it is the first method being run.

Debug validation ensures that the same pattern is not registered for
multiple protocols (as may have happened with SIP and HTTP1).

An app-layer may also register a pattern with a probing parser, meaning
that it will only recognise the protocol if: first the pattern is found,
and then the probing parser also matches.

2. Probing parser

Each app-layer protocol may register arbitrary code to recognize a protocol.
This code will only be run for some configured ports.

The probing function returns one of the 3 values
- ALPROTO_FAILED : this is definitely not the protocol
- ALPROTO_UNKNOWN : needs more data to take a decision
- ALPROTO_XYZ : if it is indeed protocol xyz

An application-layer protocol can have both a set of patterns registered,
and a probing parser.

3. Expectations

This is used now only for FTP-DATA.
A flow can set an expected flow between a source IP and a server IP+port.

Output
~~~~~~

For each flow event, we have different fields that represent the application layer protocol:

* "app_proto": the final app-layer protocol detected and parsed by Suricata
* "app_proto_tc": the app-layer protocol detected by Suricata in the direction to client, only logged if different than the app_proto
* "app_proto_ts": the app-layer protocol detected by Suricata in the direction to server, only logged if different than the app_proto
* "app_proto_orig": the original app-layer protocol detected by Suricata if the flow changed its protocol
* "app_proto_expected": the expected app-layer protocol if the flow changed its protocol to an unexpected protocol

.. note:: For detection the keyword :ref:`app-layer-protocol <rule-keyword-app-layer-protocol>`
          may be used for these different fields.

Suricata also emits anomalies about protocol detection
(for which you can use rules with ``app-layer-event`` keyword):

* APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION : only one side was recognised, the other is unknown
* APPLAYER_MISMATCH_PROTOCOL_BOTH_DIRECTIONS : the two sides were recognised but are different
* APPLAYER_PROTO_DETECTION_SKIPPED : no side was recognised
* APPLAYER_UNEXPECTED_PROTOCOL : a protocol change was requested to a specific one, but this specific protocol was not recognised
* APPLAYER_NO_TLS_AFTER_STARTTLS : same as above, but specialized for TLS
* APPLAYER_WRONG_DIRECTION_FIRST_DATA : the protocol recognised received the first data in the unexpected side (like HTTP1 flow beginning by a response)

Suricata stats events also count the number of flows per app-layer protocol :
``.stats.app_layer.flow.xyz`` for xyz protocol.
For the app-layer protocols that can be recognised above both TCP and UDP,
these counters are split in 2 fields like ``nfs_tcp`` and ``nfs_udp``.
These statistics are known to be not entirely consistent with
the number of flows for a certain app-layer protocol
(because of protocol change for a known edge case).
