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