.. role:: example-rule-emphasis

SSH Keywords
============
Suricata has several rule keywords to match on different elements of SSH
connections.

.. _ssh-hooks:

Hooks
-----

The SSH parser exposes a per-direction state machine. A rule that
hooks one of the states below is evaluated once the transaction's
progress in that direction has reached the state; for firewall rules
the verdict applies while the transaction stays at the hooked state
and stops applying once it advances past it (see :ref:`app-layer-state`).

Request (``to_server``) side:

+---------------------------+-------------------------------------------------+
| State                     | Meaning                                         |
+===========================+=================================================+
| ``request_banner``        | Version exchange: the banner (version) phase;   |
|                           | the first packets of the direction. A banner    |
|                           | line of 256 bytes or more without an            |
|                           | end-of-line keeps the direction here: the line  |
|                           | is consumed greedily until the end-of-line, and |
|                           | the condition is observable through the         |
|                           | ``ssh.long_banner`` event (the banner data is   |
|                           | published when the long line first parses).     |
+---------------------------+-------------------------------------------------+
| ``request_kex``           | A valid banner line was parsed; key exchange.   |
|                           | ``ssh.proto``, ``ssh.software`` and the hassh   |
|                           | buffers are registered at this state. A long    |
|                           | banner can publish them while the line is       |
|                           | still open; if the line never completes, the    |
|                           | values are not inspected at a clean flow end    |
|                           | (the direction stays below the registered       |
|                           | state); a flow that ends disrupted (depth       |
|                           | truncation or async reassembly) reads as past   |
|                           | this state, and the values are inspected there  |
+---------------------------+-------------------------------------------------+
| ``request_session``       | A ``new keys`` record was seen in this          |
|                           | direction: the session is established for that  |
|                           | direction; the two directions are tracked       |
|                           | independently (a parse failure in either ends   |
|                           | the flow's app-layer parsing, see Completion    |
|                           | and failure). ``new keys`` is a transition      |
|                           | rather than a phase with its own data: match    |
|                           | the record itself with a frame rule (message    |
|                           | code 21, see the example below).                |
+---------------------------+-------------------------------------------------+

Response (``to_client``) side:

+---------------------------+-------------------------------------------------+
| State                     | Meaning                                         |
+===========================+=================================================+
| ``response_banner``       | Server banner (version) phase: the same         |
|                           | behavior as ``request_banner`` above, in the    |
|                           | server-to-client direction.                     |
+---------------------------+-------------------------------------------------+
| ``response_kex``          | Server key exchange: same as                    |
|                           | ``request_kex`` — the direction's               |
|                           | ``ssh.proto`` / ``ssh.software`` and hassh      |
|                           | buffers are registered at this state.           |
+---------------------------+-------------------------------------------------+
| ``response_session``      | A ``new keys`` record was seen in the           |
|                           | server-to-client direction: same as             |
|                           | ``request_session``.                            |
+---------------------------+-------------------------------------------------+

Overly long banner lines
~~~~~~~~~~~~~~~~~~~~~~~~

A banner line of 256 bytes or more without an end-of-line keeps the
direction in the banner state. The line is consumed greedily until
the end-of-line arrives, and the direction then advances to
``kex``. The condition is observable through the ``ssh.long_banner``
app-layer event (the banner data is published when the long line
first parses). If the line does not parse as a banner when it
completes, the direction fails and is frozen in ``banner``.

Completion and failure
~~~~~~~~~~~~~~~~~~~~~~

``request_done`` / ``response_done`` is the registered completion
state. No direction ever reports it: a successful direction tops out
at ``session``, and a direction that hits an unrecoverable error —
an invalid banner or an invalid record (header or payload) — is
frozen in the state the error occurred in. It is the last progress
the direction reports, and the reason is available through
the ``ssh.invalid_banner`` / ``ssh.invalid_record`` app-layer
events and the per-direction ``error`` / ``state`` fields of the
eve ``ssh`` object (``invalid_banner`` / ``invalid_record``
and the state the failure occurred in; a failed flow is logged even when
no banner was parsed, so the error field may be its only content).
A parse failure puts the flow into an error state: nothing after
the failing packet is parsed or delivered, mid-flow or at the
flow-end flush, and the frozen state is what the progress
accessor - and thus the flow-end eve object - reports. The
``ssh.invalid_banner`` / ``ssh.invalid_record`` events are
evaluated as soon as the tx is next inspected - the failing
packet itself unless the error policy skips it - at the latest
the flow-end flush.
A keyword registered at the failed state gets no eof run (eof
requires progress above the registered state), so its flow-end
evaluation stays non-terminal; states before it were already
terminalized when the direction left them. The ``ssh.long_banner`` and
``ssh.long_kex_record`` events are non-fatal: the direction
continues (a long banner keeps it in ``banner`` until the line
completes; an oversized key-exchange record keeps it in ``kex`` until
the record has been buffered in full).

Consequences worth knowing:

* ``ssh:request_complete`` (and the firewall policy key
  ``request-complete``) is bound to the completion state, which no
  direction reports: the hook matches nothing for well-formed
  flows. A disrupted flow (depth truncation or async reassembly)
  matches, because on a disrupted flow the engine reports the
  completion state as the transaction progress instead of
  querying the parser. Before this change it matched a flow whose
  session was established. Review existing
  ``accept:* ssh:request_complete`` rules and ``request-complete``
  firewall policies: a session-admit rule like that no longer fires.
  Failures are reported through the ``ssh.invalid_banner`` /
  ``ssh.invalid_record`` events instead.
* Rules cannot reference ``done`` (``request_done`` /
  ``response_done`` do not load): it is out of both name tables.
  The generic hook lists for the completion state are registered
  under the built-in completion names
  (``ssh:request_complete:generic`` /
  ``ssh:response_complete:generic``); the state-name-based lists
  are not registered for the completion id (the id-to-name lookup
  returns null). They run only at a disrupted flow end, where the
  engine reports the completion state as the transaction progress
  instead of querying the parser - so Lua hooks on ssh completion
  no longer fire for well-formed flows; before this change the
  accessor reported the terminal state once both directions had
  sent NewKeys.
* ``app-layer-state:>request_session`` matches only directions that
  were *disrupted past session (e.g. by depth truncation or async
  reassembly)* — a successful request direction stops at
  ``request_session``, and a failed one is frozen at the state it
  failed in (use the ``ssh.invalid_*`` events for that).

For firewall rules and ``app-layer-state`` users,
:doc:`../firewall/ssh-state-migration` maps the old hook names to the
new phases and describes the behaviour changes.

Frames
------

The SSH parser supports the following frames:

* ssh.record_hdr
* ssh.record_data
* ssh.record_pdu

These are header + data = pdu for SSH records, after the banner and before encryption.
The SSH record header is 6 bytes long : 4 bytes length, 1 byte passing, 1 byte message code.

Example:

.. container:: example-rule

  alert ssh any any -> any any (msg:"hdr frame new keys"; :example-rule-emphasis:`frame:ssh.record.hdr; content: "|15|"; endswith;` bsize: 6; sid:2;)

This rule matches like Wireshark ``ssh.message_code == 0x15``.

ssh.proto
---------
Match on the version of the SSH protocol used. ``ssh.proto`` is a sticky buffer,
and can be used as a fast pattern. ``ssh.proto`` replaces the previous buffer
name: ``ssh_proto``. You may continue to use the previous name, but it's
recommended that existing rules be converted to use the new name.

Format::

  ssh.proto;

Example:

.. container:: example-rule

  alert ssh any any -> any any (msg:"match SSH protocol version"; :example-rule-emphasis:`ssh.proto;` content:"2.0"; sid:1000010;)

The example above matches on SSH connections with SSH version 2.0.


ssh.software
------------
Match on the software string from the SSH banner. ``ssh.software`` is a sticky
buffer, and can be used as fast pattern.

Format::

  ssh.software;

Example:

.. container:: example-rule

  alert ssh any any -> any any (msg:"match SSH software string"; :example-rule-emphasis:`ssh.software;` content:"openssh"; nocase; sid:1000020;)

The example above matches on SSH connections where the software string contains
"openssh".


ssh.hassh
---------

Match on hassh (md5 of hassh algorithms of client).

.. container:: example-rule

  alert ssh any any -> any any (msg:"match hassh"; \
      ssh.hassh; content:"ec7378c1a92f5a8dde7e8b7a1ddf33d1";\
      sid:1000010;)
      
``ssh.hassh`` is a 'sticky buffer'.

``ssh.hassh`` can be used as ``fast_pattern``.

ssh.hassh.string
----------------

Match on Hassh string (hassh algorithms of client).

.. container:: example-rule

  alert ssh any any -> any any (msg:"match hassh-string"; \
      ssh.hassh.string; content:"none,zlib@openssh.com,zlib"; \
      sid:1000030;)

``ssh.hassh.string`` is a 'sticky buffer'.

``ssh.hassh.string`` can be used as ``fast_pattern``.

ssh.hassh.server
----------------

Match on hassh (md5 of hassh algorithms of server).

.. container:: example-rule

  alert ssh any any -> any any (msg:"match SSH hash-server"; \
      ssh.hassh.server; content:"b12d2871a1189eff20364cf5333619ee"; \
      sid:1000020;)

``ssh.hassh.server`` is a 'sticky buffer'.

``ssh.hassh.server`` can be used as ``fast_pattern``.

ssh.hassh.server.string
-----------------------

Match on hassh string (hassh algorithms of server).

.. container:: example-rule

  alert ssh any any -> any any (msg:"match SSH hash-server-string"; \
      ssh.hassh.server.string; content:"umac-64-etm@openssh.com,umac-128-etm@openssh.com"; \
      sid:1000040;)

``ssh.hassh.server.string`` is a 'sticky buffer'.

``ssh.hassh.server.string`` can be used as ``fast_pattern``.
