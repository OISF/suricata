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
|                           | buffers are registered at this state.           |
+---------------------------+-------------------------------------------------+
| ``request_session``       | A ``new keys`` record was seen in this          |
|                           | direction: the session is established for that  |
|                           | direction (the other direction advances         |
|                           | independently). ``new keys`` is a transition    |
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
direction in the ``banner`` state: the line is consumed greedily
until the end-of-line arrives and the direction then advances to
``kex``. The condition is observable through the ``ssh.long_banner``
app-layer event (the banner data is published when the long line
first parses). If the line does not parse as a banner when it
completes, the direction fails (it jumps straight to ``done``).

Completion and failure
~~~~~~~~~~~~~~~~~~~~~~

``request_done`` / ``response_done`` is the registered completion
state and doubles as the failure state. When the parser in one
direction hits an unrecoverable error — an invalid banner or an
invalid record (header or payload) — that direction jumps straight
to ``done``. The failure is terminal for every keyword, and the
reason is available through the ``ssh.invalid_banner`` /
``ssh.invalid_record`` app-layer events and the per-direction
``error`` field of the eve ``ssh`` object (``invalid_banner`` /
``invalid_record``; a failed flow is logged even when no banner was
parsed, so the error field may be its only content). The
``ssh.long_banner`` and ``ssh.long_kex_record`` events are non-fatal:
the direction continues (a long banner keeps it in ``banner`` until
the line completes, an oversized key-exchange record keeps stashing).

Consequences worth knowing:

* A successful direction never reports ``done`` — its maximum
  progress is ``session``. The engine-level hook ``request_complete``
  (and the firewall policy key ``request-complete``) is bound to the
  completion state: before this change it matched a flow whose
  session was established, and it matches only the failure (or
  disrupted) condition now. Review existing ``accept:* ssh:request_complete``
  rules and ``request-complete`` firewall policies: a session-admit
  rule like that silently inverts.
* Rules cannot reference ``done`` (``request_done`` /
  ``response_done`` do not load), although the generic hook lists for
  the completion state are still registered (``ssh:request_done:generic``
  / ``ssh:response_done:generic``), which is what Lua hooks into. And
  ``app-layer-state:>request_session`` matches only directions that
  *failed (or were disrupted, e.g. by a stream gap or depth
  truncation)* — a successful request direction stops at
  ``request_session``.

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
