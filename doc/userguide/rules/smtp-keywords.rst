SMTP Keywords
=============

.. role:: example-rule-options

file.name
---------

The ``file.name`` keyword can be used at the SMTP application level. 

Signature Example:

.. container:: example-rule

  alert smtp any any -> any any (msg:"SMTP file.name usage"; \
  :example-rule-options:`file.name; content:"winmail.dat";` \
  classtype:bad-unknown; sid:1; rev:1;)

For additional information on the ``file.name`` keyword, see :doc:`file-keywords`.


smtp.helo
---------

SMTP helo is the parameter passed to the first HELO command from the client.
This keyword matches per transaction, so it can match more than once per flow,
even if the helo occured only once at the beginning of the flow.

Syntax::

 smtp.helo; content:"localhost";

Signature example::

 alert smtp any any -> any any (msg:"SMTP helo localhost"; smtp.helo; content:"localhost"; sid:2; rev:1;)

``smtp.helo`` is a 'sticky buffer'.

``smtp.helo`` can be used as ``fast_pattern``.

This keyword maps to the eve.json log field ``smtp.helo``

smtp.mail_from
--------------

SMTP mail from is the parameter passed to the first MAIL FROM command from the client.

Syntax::

 smtp.mail_from; content:"spam";

Signature example::

 alert smtp any any -> any any (msg:"SMTP mail from spam"; smtp.mail_from; content:"spam"; sid:2; rev:1;)

``smtp.mail_from`` is a 'sticky buffer'.

``smtp.mail_from`` can be used as ``fast_pattern``.

This keyword maps to the eve.json log field ``smtp.mail_from``

smtp.rcpt_to
------------

SMTP rcpt to is the one of the parameters passed to one RCPT TO command from the client.

Syntax::

 smtp.rcpt_to; content:"sensitive@target";

Signature example::

 alert smtp any any -> any any (msg:"SMTP rcpt to sensitive"; smtp.rcpt_to; content:"sensitive@target"; sid:2; rev:1;)

``smtp.rcpt_to`` is a 'sticky buffer'.

``smtp.rcpt_to`` is a 'multi buffer'.

``smtp.rcpt_to`` can be used as ``fast_pattern``.

This keyword maps to the eve.json log field ``smtp.rcpt_to[]``


Frames
------

The SMTP parser supports the following frames:

* smtp.command_line
* smtp.response_line
* smtp.data
* smtp.stream

smtp.command_line
~~~~~~~~~~~~~~~~~

A single line from the client to the server. Multi-line commands will have a frame per
line. Lines part of the SMTP DATA transfer are excluded.

.. container:: example-rule

  alert smtp any any -> any any ( \
  :example-rule-options:`frame:smtp.command_line; content:"MAIL|20|FROM:"; startswith;` \
  sid:1;)

smtp.response_line
~~~~~~~~~~~~~~~~~~

A single line from the server to the client. Multi-line commands will have a frame per line.

.. container:: example-rule

  alert smtp any any -> any any ( \
  :example-rule-options:`frame:smtp.response_line; content:"354 go ahead"; startswith;` \
  sid:1;)

smtp.data
~~~~~~~~~

A streaming buffer containing the DATA bytes sent from client to server.

.. container:: example-rule

  alert smtp any any -> any any ( \
  :example-rule-options:`frame:smtp.data; content:"Reply-To:"; startswith; content:"Subject"; distance:0;` \
  sid:1;)

smtp.stream
~~~~~~~~~~~

Streaming buffer of the entire TCP data for the SMTP session.

.. container:: example-rule

  alert smtp any any -> any any (flow:to_client; \
  :example-rule-options:`frame:smtp.stream; content:"250 ok|0d 0a|354 go ahead";` \
  sid:1;)
