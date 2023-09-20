FTP/FTP-DATA Keywords
=====================

ftpdata_command
---------------

Filter ftp-data channel based on command used on the FTP command channel.
Currently supported commands are RETR (get on a file) and STOR (put on a
file).

Syntax::

  ftpdata_command:(retr|stor)

Examples::

  ftpdata_command:retr
  ftpdata_command:stor

Signature example::

 alert ftp-data any any -> any any (msg:"FTP store password"; filestore; filename:"password"; ftpdata_command:stor; sid:3; rev:1;)

ftpbounce
---------

Detect FTP bounce attacks.

Syntax::

  ftpbounce

file.name
---------

The ``file.name`` keyword can be used at the FTP application level.

Example::

alert ftp-data any any -> any any (msg:"ftp layer file.name keyword usage"; \
file.name; content:"file.txt"; classtype:bad-unknown; sid:1; rev:1;)

For additional information on the ``file.name`` keyword, see :doc:`file-keywords`.