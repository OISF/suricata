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

