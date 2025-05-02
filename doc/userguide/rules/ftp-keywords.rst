FTP/FTP-DATA Keywords
=====================

.. role:: example-rule-options

ftpdata_command
---------------

Filter ftp-data channel based on command used on the FTP command channel.
Currently supported commands are RETR (get on a file) and STOR (put on a
file).

Syntax::

  ftpdata_command:(retr|stor)

Signature Example:

.. container:: example-rule

  alert ftp-data any any -> any any (msg:"FTP store password"; \
  filestore; filename:"password"; \
  :example-rule-options:`ftpdata_command:stor;` sid:3; rev:1;)

ftpbounce
---------

Detect FTP bounce attacks.

Syntax::

  ftpbounce

file.name
---------

The ``file.name`` keyword can be used at the FTP application level.

Signature Example:

.. container:: example-rule

  alert ftp-data any any -> any any (msg:"FTP file.name usage"; \
  :example-rule-options:`file.name; content:"file.txt";` \
  classtype:bad-unknown; sid:1; rev:1;)

For additional information on the ``file.name`` keyword, see :doc:`file-keywords`.

ftp.command
-----------

This keyword matches on the command name from an FTP client request. ``ftp.command``
is a sticky buffer and can be used as a fast pattern.

Syntax::

  ftp.command; content: <command>;

Signature Example:

.. container:: example-rule

  alert ftp any any -> any any (:example-rule-options:`ftp.command; content:"PASS";` sid: 1;)

Examples of commands are:

* USER
* PASS
* PORT
* EPRT
* PASV
* RETR

ftp.command_data
----------------

This keyword matches on the command data from a FTP client request.
``ftp.command_data`` is a sticky buffer and can be used as a fast pattern.

Syntax::

  ftp.command_data; content: <command_data>;

Signature Example:

.. container:: example-rule

  alert ftp any any -> any any (:example-rule-options:`ftp.command_data; content:"anonymous";` sid: 1;)


The ``ftp.command_data`` matches the data associated with an FTP command. Consider the following FTP command
examples::

    USER anonymous
    RETR temp.txt
    PORT 192,168,0,13,234,10

Example rules for each of the preceding FTP commands and command data.

.. container:: example-rule

  alert ftp any any -> any any (ftp.command; content: "USER"; :example-rule-options:`ftp.command_data; content:"anonymous";` sid: 1;)

.. container:: example-rule

  alert ftp any any -> any any (:example-rule-options:`ftp.command_data; content:"anonymous";` sid: 1;)

.. container:: example-rule

  alert ftp any any -> any any (:example-rule-options:`ftp.command_data; content:"temp.txt";` sid: 2;)

.. container:: example-rule

  alert ftp any any -> any any (:example-rule-options:`ftp.command_data; content:"192,168,0,13,234,10";` sid: 3;)

ftp.dynamic_port
----------------

This keyword matches on the dynamic port negotiated during an FTP session with
the following FTP commands:

* IPv4: ``PORT`` and ``EPRT``
* IPv6: ``PASV`` and ``EPSV``

Syntax::

  ftp.dynamic_port: <port-spec>;

``port-spec`` can be one of the following:

* ``>`` (greater than)
* ``<`` (less than)
* ``>=`` (greater than or equal)
* ``<=`` (less than or equal)
* ``arg1-arg2`` (exclusive range)

Signature Example:

.. container:: example-rule

  alert ftp any any -> any any (:example-rule-options:`ftp.dynamic_port: 59914;` sid: 1;)

These rules are will also alert on port ``59914``:

.. container:: example-rule

  alert ftp any any -> any any (:example-rule-options:`ftp.dynamic_port: 59913-59915;` sid: 1;)

.. container:: example-rule

  alert ftp any any -> any any (:example-rule-options:`ftp.dynamic_port: =59914;` sid: 1;)

Example rules combining ``ftp.dynamic_port`` with ``ftp.command``

.. container:: example-rule

  alert ftp any any -> any any (ftp.command; content: "PORT"; :example-rule-options:`ftp.dynamic_port: 59914;` sid: 1;)

.. container:: example-rule

  alert ftp any any -> any any (ftp.command; content: "EPSV"; :example-rule-options:`ftp.dynamic_port: 58612;` sid: 1;)

ftp.mode
--------

This keyword matches on whether the FTP session is dynamic or passive.
In `active` mode sessions, the server establishes the data channel.
In `passive` mode, the client establishes the data channel. Active
mode sessions are established in part with the ``PORT`` (``EPRT`` for IPv6)
command; passive mode sessions use ``PASV`` (``EPSV`` for IPv6).

Syntax::

  ftp.mode: active|passive;

Signature Example:

.. container:: example-rule

  alert ftp any any -> any any (:example-rule-options:`ftp.mode: active;` sid: 1;)

.. container:: example-rule

  alert ftp any any -> any any (:example-rule-options:`ftp.mode: passive;` sid: 1;)

Example rules combining ``ftp.command`` with ``ftp.mode``

.. container:: example-rule

  alert ftp any any -> any any (ftp.command; content: "PORT"; :example-rule-options:`ftp.mode: active;` sid:1;)

.. container:: example-rule

  alert ftp any any -> any any (ftp.command; content: "PASV"; :example-rule-options:`ftp.mode: passive;` sid:1;)

ftp.reply
---------

This keyword matches on an FTP reply string. Note that there may be multiple reply strings for
an FTP command. ``ftp.reply`` is a sticky buffer and can be used as a fast pattern. Do not
include the completion code in the `content` to match upon (see examples).

Syntax::

  ftp.reply; content: <reply-string>;

.. note ::
   FTP commands can return multiple reply strings. Specify a single reply for each ``ftp.reply`` keyword.

This example shows an FTP command (``RETR``) followed by an FTP reply with multiple response strings.
::

    RETR temp.txt
    150 Opening BINARY mode data connection for temp.txt (1164 bytes).
    226 Transfer complete.

Signature Example:

.. container:: example-rule

  alert ftp any any -> any any (:example-rule-options:`ftp.reply; content:"Please specify the password.";` sid: 1;)

.. container:: example-rule

  alert ftp any any -> any any (:example-rule-options:`ftp.reply; content:"Opening BINARY mode data connection for temp.";` sid: 1;)

.. container:: example-rule

  alert ftp any any -> any any (:example-rule-options:`ftp.reply; content:"Transfer complete.";` sid: 2;)
