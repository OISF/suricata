Generic App Layer Keywords
==========================

.. _rule-keyword-app-layer-protocol:

app-layer-protocol
------------------

Match on the detected app-layer protocol.

Syntax::

    app-layer-protocol:[!]<protocol>(,<mode>);
    app-layer-protocol:[!]<proto1>,<proto2>[,...,<protoN>](,<mode>);

Examples::

    app-layer-protocol:ssh;
    app-layer-protocol:!tls;
    app-layer-protocol:failed;
    app-layer-protocol:!http,final;
    app-layer-protocol:http,to_server; app-layer-protocol:tls,to_client;
    app-layer-protocol:http2,final; app-layer-protocol:http1,original;
    app-layer-protocol:unknown;
    app-layer-protocol:unknown,tls;
    app-layer-protocol:unknown,tls,http;
    app-layer-protocol:!tls,http;
    app-layer-protocol:tls,http,either;

A special value 'failed' can be used for matching on flows in which
protocol detection failed. This can happen if Suricata doesn't know
the protocol or when certain 'bail out' conditions happen.

A special value 'unknown' can be used to match on a protocol being
not yet known. It can not be negated.

The different modes are
* direction : protocol recognized on the direction of the current packet
* to_server : protocol recognized in the direction to server
* to_client : protocol recognized in the direction to client
* either : tries to match protocols found on both directions
* final : final protocol chosen by Suricata for parsing
* original : original protocol (in case of protocol change)

By default, (if no mode is specified), the mode is ``direction``.

.. note:: when negation is used, like ``!http``, it will not match on the
   "unknown" state in the flow.

Here is an example of a rule matching non-http traffic on port 80:

.. container:: example-rule

    alert tcp any any -> any 80 (msg:"non-HTTP traffic over HTTP standard port"; flow:to_server; app-layer-protocol:!http,final; sid:1; )

Multi-value form
~~~~~~~~~~~~~~~~

The ``app-layer-protocol`` keyword also accepts a comma-separated list of
protocol values. A rule matches when the flow's resolved application-layer
protocol equals **any** value in the list (logical OR).

Syntax::

    app-layer-protocol:[!]<proto1>,<proto2>[,...,<protoN>](,<mode>);

The list may contain up to 16 protocol values. The total argument length
must not exceed 1024 characters, and each individual token must not exceed
50 characters.

Examples::

    app-layer-protocol:unknown,tls;
    app-layer-protocol:unknown,tls,http;
    app-layer-protocol:tls,http,either;
    app-layer-protocol:!tls,http;

Mode disambiguation rule
^^^^^^^^^^^^^^^^^^^^^^^^

When the keyword argument contains two or more comma-separated tokens, the
parser applies the following disambiguation rule to determine whether the
final token is a mode qualifier or a protocol value:

- If the final token matches one of the six recognized mode qualifier names
  (``final``, ``original``, ``either``, ``to_server``, ``to_client``,
  ``direction``), it is parsed as the mode qualifier and the preceding tokens
  form the protocol value list.
- Otherwise, all tokens are parsed as protocol values and the mode defaults
  to ``direction``.

For example::

    app-layer-protocol:tls,http,either;

Here ``either`` is recognized as a mode qualifier, so the protocol list is
``[tls, http]`` with mode ``either``.

::

    app-layer-protocol:unknown,tls,http;

Here ``http`` is not a recognized mode qualifier name, so all three tokens
are protocol values with the default mode ``direction``.

The ``unknown,<proto>`` Detection Window idiom
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When Suricata has not yet classified a flow's protocol (the "detection
window"), the flow's app-layer protocol is ``unknown``. Once protocol
detection completes, the protocol transitions to its classified value
(e.g., ``tls``, ``http``). Including ``unknown`` in a multi-value list
allows a single rule to cover both the detection window and the confirmed
protocol::

    app-layer-protocol:unknown,tls;

This rule matches during the detection window (while the protocol is still
``unknown``) **and** after classification (when the protocol is ``tls``).
If the flow is classified to a protocol not in the list (e.g., ``http``),
the rule stops matching after the detection window closes and the
default-drop verdict applies if no other rule accepts the flow.

The detection window is bounded by Suricata's existing app-layer probing
budget. No new configuration knob is introduced.

Negated multi-value (NOR semantics)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When the multi-value form is negated with ``!``, it implements NOR semantics
across the entire list: the rule matches when the resolved application-layer
protocol is **known** AND matches **none** of the listed values.

Example::

    app-layer-protocol:!tls,http;

This matches when the flow's protocol is known and is neither ``tls`` nor
``http`` (e.g., it matches ``dns``, ``ssh``, ``smtp``, etc.).

.. note:: Negated multi-value rules do not match during the detection window
   (when the protocol is still ``unknown``). This prevents false positives
   before protocol classification is complete.

.. note:: The value ``unknown`` cannot appear in a negated list. The parser
   rejects ``!unknown`` and ``!unknown,tls`` at rule-load time.

.. _proto-detect-bail-out:

Bail out conditions
~~~~~~~~~~~~~~~~~~~

Protocol detection gives up in several cases:

* both sides are inspected and no match was found
* side A detection failed, side B has no traffic at all (e.g. FTP data channel)
* side A detection failed, side B has so little data detection is inconclusive

In these last 2 cases the ``app-layer-event:applayer_proto_detection_skipped``
is set.


app-layer-event
---------------

Match on events generated by the App Layer Parsers and the protocol detection
engine.

Syntax::

  app-layer-event:<event name>;

Examples::

    app-layer-event:applayer_mismatch_protocol_both_directions;
    app-layer-event:http.gzip_decompression_failed;

Protocol Detection
~~~~~~~~~~~~~~~~~~

applayer_mismatch_protocol_both_directions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The toserver and toclient directions have different protocols. For example a
client talking HTTP to a SSH server.

applayer_wrong_direction_first_data
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Some protocol implementations in Suricata have a requirement with regards to
the first data direction. The HTTP parser is an example of this.

https://redmine.openinfosecfoundation.org/issues/993

applayer_detect_protocol_only_one_direction
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Protocol detection only succeeded in one direction. For FTP and SMTP this is
expected.

applayer_proto_detection_skipped
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Protocol detection was skipped because of :ref:`proto-detect-bail-out`.

app-layer-state
---------------

Match on the detected app-layer protocol transaction state.

Syntax::

    app-layer-state:[<>]<state>;

Examples::

    app-layer-state:request_headers;
    app-layer-state:>request_body;
