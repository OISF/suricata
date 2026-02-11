IMAP Keywords
=============

.. role:: example-rule-action
.. role:: example-rule-header
.. role:: example-rule-options
.. role:: example-rule-emphasis

imap.request
------------

Matches on IMAP request lines sent from the client to the server.

Each buffer is a request line as sent by the client, without the trailing
CRLF or bare LF. Literal data is not part of the buffer. Unlike the EVE
``imap.requests`` field, ``LOGIN`` and ``AUTHENTICATE`` arguments are not
redacted.

Syntax::

 imap.request; content:"<content to match against>";

``imap.request`` is a 'sticky buffer' and can be used as a ``fast_pattern``.

``imap.request`` supports multiple buffer matching, see :doc:`multi-buffer-matching`.

This keyword maps to the EVE field ``imap.requests[]``

Examples
^^^^^^^^

Example of a signature that would alert if an IMAP request contains a LOGIN command:

.. container:: example-rule

  alert imap any any -> any any (msg:"IMAP LOGIN request"; :example-rule-emphasis:`imap.request; content:"LOGIN";` sid:1;)

imap.response
-------------

Matches on IMAP response lines sent from the server to the client.

Syntax::

 imap.response; content:"<content to match against>";

``imap.response`` is a 'sticky buffer' and can be used as a ``fast_pattern``.

``imap.response`` supports multiple buffer matching, see :doc:`multi-buffer-matching`.

This keyword maps to the EVE field ``imap.responses[]``

A transaction keeps at most ``app-layer.protocols.imap.max-responses`` response
lines (4096 by default) plus the tagged reply that completes the command. Later
lines are neither inspected nor logged, and the first of them raises
``imap.too_many_responses``.

Examples
^^^^^^^^

Example of a signature that would alert if an IMAP response contains "OK":

.. container:: example-rule

  alert imap any any -> any any (msg:"IMAP OK response"; :example-rule-emphasis:`imap.response; content:"OK";` sid:1;)

Frames
------

The IMAP parser supports the following frames:

* imap.pdu

imap.pdu
^^^^^^^^

A single IMAP request or response PDU. Each command from the client or
response line from the server creates a separate frame.

The octets of a literal are a frame of their own, following the frame of the
line that announces the literal. The text that follows a literal on the same
line, such as the password in ``A1 LOGIN {5}`` / ``alice "secret"``, is in no
frame: use ``imap.request`` or ``imap.response`` to match on it.

.. container:: example-rule

  alert imap any any -> any any (\
  :example-rule-options:`frame:imap.pdu; content:"LOGIN";` \
  sid:1;)
