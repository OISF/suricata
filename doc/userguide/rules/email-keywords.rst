Email Keywords
==============

.. role:: example-rule-emphasis

email.from
----------

Matches the MIME ``From`` field of an email.

Comparison is case-sensitive.

Works with both SMTP and IMAP protocols.

Syntax::

 email.from; content:"<content to match against>";

``email.from`` is a 'sticky buffer' and can be used as a ``fast_pattern``.

This keyword maps to the EVE field ``email.from``

Example
^^^^^^^

Example of a signature that would alert if a packet contains the MIME field ``from`` with the value ``toto <toto@gmail.com>``

.. container:: example-rule

  alert smtp any any -> any any (msg:"Test mime email from"; :example-rule-emphasis:`email.from; content:"toto <toto@gmail.com>";` sid:1;)

email.subject
-------------

Matches the MIME ``Subject`` field of an email.

Comparison is case-sensitive.

Works with both SMTP and IMAP protocols.

Syntax::

 email.subject; content:"<content to match against>";

``email.subject`` is a 'sticky buffer' and can be used as a ``fast_pattern``.

This keyword maps to the EVE field ``email.subject``

Example
^^^^^^^

Example of a signature that would alert if a packet contains the MIME field ``subject`` with the value ``This is a test email``

.. container:: example-rule

  alert smtp any any -> any any (msg:"Test mime email subject"; :example-rule-emphasis:`email.subject; content:"This is a test email";` sid:1;)

email.to
--------

Matches the MIME ``To`` field of an email.

Comparison is case-sensitive.

Works with both SMTP and IMAP protocols.

Syntax::

 email.to; content:"<content to match against>";

``email.to`` is a 'sticky buffer' and can be used as a ``fast_pattern``.

This keyword maps to the EVE field ``email.to``

Example
^^^^^^^

Example of a signature that would alert if a packet contains the MIME field ``to`` with the value ``172.16.92.2@linuxbox``

.. container:: example-rule

  alert smtp any any -> any any (msg:"Test mime email to"; :example-rule-emphasis:`email.to; content:"172.16.92.2@linuxbox";` sid:1;)

email.cc
--------

Matches the MIME ``Cc`` field of an email.

Comparison is case-sensitive.

Works with both SMTP and IMAP protocols.

Syntax::

 email.cc; content:"<content to match against>";

``email.cc`` is a 'sticky buffer' and can be used as a ``fast_pattern``.

This keyword maps to the EVE field ``email.cc[]``

Example
^^^^^^^

Example of a signature that would alert if a packet contains the MIME field ``cc`` with the value ``Emily <emily.roberts@example.com>, Ava <ava.johnson@example.com>, Sophia Wilson <sophia.wilson@example.com>``

.. container:: example-rule

  alert smtp any any -> any any (msg:"Test mime email cc"; :example-rule-emphasis:`email.cc; content:"Emily <emily.roberts@example.com>, Ava <ava.johnson@example.com>, Sophia Wilson <sophia.wilson@example.com>";` sid:1;)

email.date
----------

Matches the MIME ``Date`` field of an email.

Comparison is case-sensitive.

Works with both SMTP and IMAP protocols.

Syntax::

 email.date; content:"<content to match against>";

``email.date`` is a 'sticky buffer' and can be used as a ``fast_pattern``.

This keyword maps to the EVE field ``email.date``

Example
^^^^^^^

Example of a signature that would alert if a packet contains the MIME field ``date`` with the value ``Fri, 21 Apr 2023 05:10:36 +0000``

.. container:: example-rule

  alert smtp any any -> any any (msg:"Test mime email date"; :example-rule-emphasis:`email.date; content:"Fri, 21 Apr 2023 05:10:36 +0000";` sid:1;)

email.message_id
----------------

Matches the MIME ``Message-Id`` field of an email.

Comparison is case-sensitive.

Works with both SMTP and IMAP protocols.

Syntax::

 email.message_id; content:"<content to match against>";

``email.message_id`` is a 'sticky buffer' and can be used as a ``fast_pattern``.

This keyword maps to the EVE field ``email.message_id``

Example
^^^^^^^

Example of a signature that would alert if a packet contains the MIME field ``message id`` with the value ``<alpine.DEB.2.00.1311261630120.9535@sd-26634.dedibox.fr>``

.. container:: example-rule

  alert smtp any any -> any any (msg:"Test mime email message id"; :example-rule-emphasis:`email.message_id; content:"<alpine.DEB.2.00.1311261630120.9535@sd-26634.dedibox.fr>";` sid:1;)

email.x_mailer
--------------

Matches the MIME ``X-Mailer`` field of an email.

Comparison is case-sensitive.

Works with both SMTP and IMAP protocols.

Syntax::

 email.x_mailer; content:"<content to match against>";

``email.x_mailer`` is a 'sticky buffer' and can be used as a ``fast_pattern``.

This keyword maps to the EVE field ``email.x_mailer``

Example
^^^^^^^

Example of a signature that would alert if a packet contains the MIME field ``x-mailer`` with the value ``Microsoft Office Outlook, Build 11.0.5510``

.. container:: example-rule

  alert smtp any any -> any any (msg:"Test mime email x-mailer"; :example-rule-emphasis:`email.x_mailer; content:"Microsoft Office Outlook, Build 11.0.5510";` sid:1;)

email.url
---------

Matches ``URL`` extracted of an email.

Comparison is case-sensitive.

This keyword works with SMTP only.

Syntax::

 email.url; content:"<content to match against>";

``email.url`` is a 'sticky buffer' and can be used as a ``fast_pattern``.

``email.url`` supports multiple buffer matching, see :doc:`multi-buffer-matching`.

This keyword maps to the EVE field ``email.url[]``

Example
^^^^^^^

Example of a signature that would alert if an email contains the ``url`` ``test-site.org/blah/123/``.

.. container:: example-rule

  alert smtp any any -> any any (msg:"Test mime email url"; :example-rule-emphasis:`email.url; content:"test-site.org/blah/123/";` sid:1;)

email.received
--------------

Matches ``Received`` field of an email.

Comparison is case-sensitive.

Works with both SMTP and IMAP protocols.

Syntax::

 email.received; content:"<content to match against>";

``email.received`` is a 'sticky buffer' and can be used as a ``fast_pattern``.

``email.received`` supports multiple buffer matching, see :doc:`multi-buffer-matching`.

This keyword maps to the EVE field ``email.received[]``

Example
^^^^^^^

Example of a signature that would alert if a packet contains the MIME field ``received`` with the value ``from [65.201.218.30] (helo=COZOXORY.club)by 173-66-46-112.wash.fios.verizon.net with esmtpa (Exim 4.86)(envelope-from )id 71cF63a9for mirjam@abrakadabra.ch; Mon, 29 Jul 2019 17:01:45 +0000``

.. container:: example-rule

  alert smtp any any -> any any (msg:"Test mime email received"; :example-rule-emphasis:`email.received; content:"from [65.201.218.30] (helo=COZOXORY.club)by 173-66-46-112.wash.fios.verizon.net with esmtpa (Exim 4.86)(envelope-from )id 71cF63a9for mirjam@abrakadabra.ch\; Mon, 29 Jul 2019 17:01:45 +0000";` sid:1;)

email.command
-------------

Matches on the lowercased IMAP command name associated with an email transfer.
For example, ``append`` when the client uploads a message, or ``fetch`` when a
message is retrieved from the server.

This keyword works with IMAP only.

Syntax::

 email.command; content:"<command>";

``email.command`` is a 'sticky buffer' and can be used as a ``fast_pattern``.

This keyword maps to the EVE field ``email.command``

Examples
^^^^^^^^

Example of a signature that would alert if an email is being uploaded via APPEND:

.. container:: example-rule

  alert imap any any -> any any (msg:"IMAP APPEND email"; :example-rule-emphasis:`email.command; content:"append";` sid:1;)

Example of a signature that would alert if an email is being fetched:

.. container:: example-rule

  alert imap any any -> any any (msg:"IMAP FETCH email"; :example-rule-emphasis:`email.command; content:"fetch";` sid:1;)

email.body
----------

Matches on the body content of an email transferred over IMAP.

This keyword works with IMAP only.

Syntax::

 email.body; content:"<content to match against>";

``email.body`` is a 'sticky buffer' and can be used as a ``fast_pattern``.

Example
^^^^^^^

Example of a signature that would alert if the email body contains "confidential":

.. container:: example-rule

  alert imap any any -> any any (msg:"IMAP email body match"; :example-rule-emphasis:`email.body; content:"confidential";` sid:1;)

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

The ``email.header`` buffer combines these as ``name: value`` (with a colon and
space separator), so a header originally written as ``Content-Type: text/plain``
is presented as ``content_type: text/plain``.

email.header
------------

Matches on email headers in normalized ``name: value`` format.

This keyword works with IMAP only.

Syntax::

 email.header; content:"<content to match against>";

``email.header`` is a 'sticky buffer' and can be used as a ``fast_pattern``.

``email.header`` supports multiple buffer matching, see :doc:`multi-buffer-matching`.

Example
^^^^^^^

Example of a signature that would alert if the email has a subject header:

.. container:: example-rule

  alert imap any any -> any any (msg:"IMAP email header match"; :example-rule-emphasis:`email.header; content:"subject";` sid:1;)

email.header.name
-----------------

Matches on email header names only (normalized: lowercase, hyphens replaced by underscores).

This keyword works with IMAP only.

Syntax::

 email.header.name; content:"<content to match against>";

``email.header.name`` is a 'sticky buffer' and can be used as a ``fast_pattern``.

``email.header.name`` supports multiple buffer matching, see :doc:`multi-buffer-matching`.

Example
^^^^^^^

Example of a signature that would alert if the email contains a "subject" header:

.. container:: example-rule

  alert imap any any -> any any (msg:"IMAP email header name match"; :example-rule-emphasis:`email.header.name; content:"subject";` sid:1;)

email.header.value
------------------

Matches on email header values only (trimmed of leading/trailing whitespace, folded lines unfolded).

This keyword works with IMAP only.

Syntax::

 email.header.value; content:"<content to match against>";

``email.header.value`` is a 'sticky buffer' and can be used as a ``fast_pattern``.

``email.header.value`` supports multiple buffer matching, see :doc:`multi-buffer-matching`.

Example
^^^^^^^

Example of a signature that would alert if an email header value contains a specific address:

.. container:: example-rule

  alert imap any any -> any any (msg:"IMAP email header value match"; :example-rule-emphasis:`email.header.value; content:"user@example.com";` sid:1;)

email.body_md5
--------------

Matches the ``md5`` hash generated from an email body.
This keyword only works if config option
``app-layer.protocols.smtp.mime.body-md5`` is enabled or auto.
It should be used with ``requires: keyword email.body_md5;``

Syntax::

 email.body_md5; content:"<content to match against>";

``email.body_md5`` is a 'sticky buffer' and can be used as a ``fast_pattern``.

This keyword maps to the EVE field ``email.body_md5``.

Example
^^^^^^^

Example of a signature that would alert if the hash ``ed00c81b85fa455d60e19f1230977134``
is generated from an email body:

.. container:: example-rule

  alert smtp any any -> any any (msg:"Test mime email body_md5"; :example-rule-emphasis:`requires: keyword email.body_md5; email.body_md5; content:"ed00c81b85fa455d60e19f1230977134";` sid:1;)
