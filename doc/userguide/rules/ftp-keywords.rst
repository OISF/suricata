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

This keyword matches on the command name from a FTP client request. ``ftp.command``
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


ftp.reply
---------

This keyword matches on a FTP reply string. Note that there may be multiple reply strings for
an FTP command. ``ftp.reply`` is a sticky buffer and can be used as a fast pattern. Do not
include the completion code.

Syntax::

  ftp.reply; content: <reply-string>;

Signature Example:

.. container:: example-rule

  alert ftp any any -> any any (:example-rule-options:`ftp.reply; content:"Please specify the password.";` sid: 1;)

.. note ::
   FTP commands can return multiple reply strings. Specify a single reply for each ``ftp.reply`` keyword.

::

    RETR temp.txt
    150 Opening BINARY mode data connection for temp.txt (1164 bytes).
    226 Transfer complete.

Signature Example:

.. container:: example-rule

  alert ftp any any -> any any (:example-rule-options:`ftp.reply; content:"Opening BINARY mode data connection for temp.";` sid: 1;)
  alert ftp any any -> any any (:example-rule-options:`ftp.reply; content:"Transfer complete.";` sid: 2;)
