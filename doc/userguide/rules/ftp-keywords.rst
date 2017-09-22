FTP/FTP-DATA Keywords
=====================

ftpcommand
----------

Filter ftp-data channel based on command used on the FTP command channel.
Currently supported commands are RETR (get on a file) and STOR (put on a
file)

Syntax::

  ftpcommand:(retr|stor)

Examples::

  ftpcommand:retr
  ftpcommand:stor

Signature example::

 alert ftp-data any any -> any any (msg:"FTP store password"; filestore; filename:"password"; ftpcommand:stor; sid:3; rev:1;)

ftpbounce
---------

Detect FTP bounce attacks

Syntax::

  ftpbounce
