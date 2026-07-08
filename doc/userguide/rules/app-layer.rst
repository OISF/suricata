Generic App Layer Keywords
==========================

.. _rule-keyword-app-layer-protocol:

app-layer-protocol
------------------

Match on the detected app-layer protocol.

Syntax::

    app-layer-protocol:[!]<protocol>[,<qualifier>]...;
    app-layer-protocol:[!]<proto1>|<proto2>[|...|<protoN>][,<qualifier>]...;

Each ``<qualifier>`` is either a ``<mode>`` (at most one, see below) or the
``exact`` option, in any order.

Examples::

    app-layer-protocol:ssh;
    app-layer-protocol:!tls;
    app-layer-protocol:failed;
    app-layer-protocol:!http,final;
    app-layer-protocol:http,to_server; app-layer-protocol:tls,to_client;
    app-layer-protocol:http2,final; app-layer-protocol:http1,original;
    app-layer-protocol:unknown;
    app-layer-protocol:unknown|tls;
    app-layer-protocol:unknown|tls|http;
    app-layer-protocol:!tls|http;
    app-layer-protocol:tls|http,either;
    app-layer-protocol:dns,exact;
    app-layer-protocol:tls|dns,either,exact;

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

Protocol equivalences and the ``exact`` option
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

By default a value matches its related protocols as well as itself. For
example ``http`` matches ``http1`` and ``http2``, ``dns`` also matches
``doh2`` (DNS over HTTP/2), and ``dcerpc`` also matches ``smb``. This is the
long-standing behaviour and keeps existing rules working.

Add the ``exact`` qualifier to match strictly, with no equivalences: the
flow's protocol must equal the configured value exactly. ``exact`` applies to
all values in the list and can be combined with a mode::

    app-layer-protocol:dns,exact;          # matches dns only, not doh2
    app-layer-protocol:tls|dns,either,exact;

Because ``exact`` disables all equivalences, the generic ``http`` value is not
expanded to ``http1``/``http2`` either. A flow is never classified as the
generic ``http``, so ``app-layer-protocol:http,exact`` can never match and is
rejected at rule load; use ``http1`` or ``http2`` instead.

Here is an example of a rule matching non-http traffic on port 80:

.. container:: example-rule

    alert tcp any any -> any 80 (msg:"non-HTTP traffic over HTTP standard port"; flow:to_server; app-layer-protocol:!http,final; sid:1; )

Multi-value form
~~~~~~~~~~~~~~~~

The ``app-layer-protocol`` keyword also accepts a pipe-separated (``|``) list
of protocol values. A rule matches when the flow's resolved application-layer
protocol equals **any** value in the list (logical OR).

Syntax::

    app-layer-protocol:[!]<proto1>|<proto2>[|...|<protoN>](,<mode>);

Using ``|`` for the list keeps the optional trailing ``,<mode>`` qualifier
unambiguous, so the single-value ``<protocol>,<mode>`` form is unchanged.

Examples::

    app-layer-protocol:unknown|tls;
    app-layer-protocol:unknown|tls|http;
    app-layer-protocol:tls|http,either;
    app-layer-protocol:!tls|http;

The ``unknown|<proto>`` detection-window idiom
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When Suricata has not yet classified a flow's protocol (the "detection
window"), the flow's app-layer protocol is ``unknown``. Once protocol
detection completes, the protocol transitions to its classified value
(e.g., ``tls``, ``http``). Including ``unknown`` in a multi-value list
allows a single rule to cover both the detection window and the confirmed
protocol::

    app-layer-protocol:unknown|tls;

This rule matches during the detection window (while the protocol is still
``unknown``) **and** after classification (when the protocol is ``tls``).
If the flow is classified to a protocol not in the list (e.g., ``http``),
the rule stops matching once the protocol is classified; in firewall mode the
flow is then handled by the default policy if no other rule accepts it.

Negated multi-value (NOR semantics)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When the multi-value form is negated with ``!``, it implements NOR semantics
across the entire list: the rule matches when the resolved application-layer
protocol is **known** AND matches **none** of the listed values.

Example::

    app-layer-protocol:!tls|http;

This matches when the flow's protocol is known and is neither ``tls`` nor
``http`` (e.g., it matches ``dns``, ``ssh``, ``smtp``, etc.).

.. note:: Negated multi-value rules do not match during the detection window
   (when the protocol is still ``unknown``). This prevents false positives
   before protocol classification is complete.

.. note:: The value ``unknown`` cannot appear in a negated list. The parser
   rejects ``!unknown`` and ``!unknown|tls`` at rule-load time.

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
