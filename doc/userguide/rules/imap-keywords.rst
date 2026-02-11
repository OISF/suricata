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

imap.email.direction
--------------------

Matches on the direction of an email transferred over IMAP.

Syntax::

 imap.email.direction: direction;

.. table:: **Direction values for imap.email.direction**

        =====  ===========
        Value  Name
        =====  ===========
        0      to_server
        1      to_client
        =====  ===========

imap.email.direction uses :ref:`unsigned 8-bit integer <rules-integer-keywords>`.

This keyword maps to the EVE field ``imap.email.direction``

Examples
^^^^^^^^

Example of a signature that would alert if an email is being sent to the server (e.g. APPEND):

.. container:: example-rule

  alert imap any any -> any any (msg:"IMAP email to server"; :example-rule-emphasis:`imap.email.direction:to_server;` sid:1;)

.. container:: example-rule

  alert imap any any -> any any (msg:"IMAP email to server"; :example-rule-emphasis:`imap.email.direction:0;` sid:1;)

Example of a signature that would alert if an email is being fetched from the server:

.. container:: example-rule

  alert imap any any -> any any (msg:"IMAP email to client"; :example-rule-emphasis:`imap.email.direction:to_client;` sid:1;)

imap.email.body
---------------

Matches on the body content of an email transferred over IMAP.

Syntax::

 imap.email.body; content:"<content to match against>";

``imap.email.body`` is a 'sticky buffer' and can be used as a ``fast_pattern``.

This keyword maps to the EVE field ``imap.email.body``

Examples
^^^^^^^^

Example of a signature that would alert if the email body contains "confidential":

.. container:: example-rule

  alert imap any any -> any any (msg:"IMAP email body match"; :example-rule-emphasis:`imap.email.body; content:"confidential";` sid:1;)

Email Header Normalization
--------------------------

Email headers are normalized before matching:

- **Header names** are converted to lowercase with hyphens replaced by underscores
  (e.g. ``Content-Type`` becomes ``content_type``).
- **Header values** have leading and trailing whitespace trimmed.
- **Folded headers** (multi-line headers per RFC 5322) are unfolded: the CRLF and
  leading whitespace of continuation lines are replaced by a single space
  (e.g. ``Subject: very long\r\n  value`` becomes ``very long value``).
- When the same header appears multiple times, each occurrence is exposed as a
  separate buffer.

The ``imap.email.header`` buffer combines these as ``name: value`` (with a colon and
space separator), so a header originally written as ``Content-Type: text/plain``
is presented as ``content_type: text/plain``.

imap.email.header
-----------------

Matches on IMAP email headers in normalized ``name: value`` format.

Syntax::

 imap.email.header; content:"<content to match against>";

``imap.email.header`` is a 'sticky buffer' and can be used as a ``fast_pattern``.

``imap.email.header`` supports multiple buffer matching, see :doc:`multi-buffer-matching`.

This keyword maps to the EVE field ``imap.email.headers``

Examples
^^^^^^^^

Example of a signature that would alert if the email has a subject header:

.. container:: example-rule

  alert imap any any -> any any (msg:"IMAP email header match"; :example-rule-emphasis:`imap.email.header; content:"subject";` sid:1;)

imap.email.header.name
-----------------------

Matches on IMAP email header names only (normalized: lowercase, hyphens replaced by underscores).

Syntax::

 imap.email.header.name; content:"<content to match against>";

``imap.email.header.name`` is a 'sticky buffer' and can be used as a ``fast_pattern``.

``imap.email.header.name`` supports multiple buffer matching, see :doc:`multi-buffer-matching`.

Examples
^^^^^^^^

Example of a signature that would alert if the email contains a "subject" header:

.. container:: example-rule

  alert imap any any -> any any (msg:"IMAP email header name match"; :example-rule-emphasis:`imap.email.header.name; content:"subject";` sid:1;)

imap.email.header.value
------------------------

Matches on IMAP email header values only (trimmed of leading/trailing whitespace, folded lines unfolded).

Syntax::

 imap.email.header.value; content:"<content to match against>";

``imap.email.header.value`` is a 'sticky buffer' and can be used as a ``fast_pattern``.

``imap.email.header.value`` supports multiple buffer matching, see :doc:`multi-buffer-matching`.

Examples
^^^^^^^^

Example of a signature that would alert if an email header value contains a specific address:

.. container:: example-rule

  alert imap any any -> any any (msg:"IMAP email header value match"; :example-rule-emphasis:`imap.email.header.value; content:"user@example.com";` sid:1;)

Frames
------

The IMAP parser supports the following frames:

* imap.pdu
* imap.headers
* imap.body

imap.pdu
^^^^^^^^

A single IMAP request or response PDU. Each command from the client or
response line from the server creates a separate frame.

.. container:: example-rule

  alert imap any any -> any any (\
  :example-rule-options:`frame:imap.pdu; content:"LOGIN"; startswith;` \
  sid:1;)

imap.headers
^^^^^^^^^^^^

The email headers portion of a literal data transfer (e.g. during an APPEND command).
This frame covers the raw header bytes up to the blank line separating headers from
the body.

.. container:: example-rule

  alert imap any any -> any any (\
  :example-rule-options:`frame:imap.headers; content:"Subject";` \
  sid:1;)

imap.body
^^^^^^^^^

The email body portion of a literal data transfer. This frame starts after the blank
line that terminates the headers and covers the remaining bytes of the email content.

.. container:: example-rule

  alert imap any any -> any any (\
  :example-rule-options:`frame:imap.body; content:"confidential";` \
  sid:1;)
