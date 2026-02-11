IMAP Keywords
=============

.. role:: example-rule-action
.. role:: example-rule-header
.. role:: example-rule-options
.. role:: example-rule-emphasis

imap.request
------------

Matches on IMAP request lines sent from the client to the server.

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

.. container:: example-rule

  alert imap any any -> any any (\
  :example-rule-options:`frame:imap.pdu; content:"LOGIN"; startswith;` \
  sid:1;)
