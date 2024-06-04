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

.. container:: example fule

  alert smtp any any -> any any ( \
  :example-rule-options:`frame:smtp.command_line; content:"MAIL|20|FROM:"; startswith;` \
  sid:1;)

smtp.response_line
~~~~~~~~~~~~~~~~~~

A single line from the server to the client. Multi-line commands will have a frame per line.

.. container:: example fule

  alert smtp any any -> any any ( \
  :example-rule-options:`frame:smtp.response_line; content:"354 go ahead"; startswith;` \
  sid:1;)

smtp.data
~~~~~~~~~

A streaming buffer containing the DATA bytes sent from client to server.

.. container:: example fule

  alert smtp any any -> any any ( \
  :example-rule-options:`frame:smtp.data; content:"Reply-To:"; startswith; content:"Subject"; distance:0;` \
  sid:1;)

smtp.stream
~~~~~~~~~~~

Streaming buffer of the entire TCP data for the SMTP session.

.. container:: example fule

  alert smtp any any -> any any (flow:to_client; \
  :example-rule-options:`frame:smtp.stream; content:"250 ok|0d 0a|354 go ahead";` \
  sid:1;)
