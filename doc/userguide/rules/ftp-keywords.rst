FTP Keywords
============

The FTP keywords are implemented as sticky buffers and can be used to match on fields in FTP requests.

============================== ==================
Keyword                        Direction
============================== ==================
ftp.command                    Request
============================== ==================

ftp.command
-----------

This keyword matches on the command name from a FTP client request.

Syntax
~~~~~~

::

  ftp.command; content:<command>;

Examples of commands are:

* PORT
* EPRT
* PASV
* USER
* PASS

Examples
~~~~~~~~

::

  ftp.command; content:"PASS";

