SMTP Keywords
=============

file.name
---------

The ``file.name`` keyword can be used at the SMTP application level. 

Example::

  alert smtp any any -> any any (msg:"smtp layer file.name keyword usage"; \
 file.name; content:"winmail.dat"; classtype:bad-unknown; sid:1; rev:1;)


For additional information on the ``file.name`` keyword, see :doc:`file-keywords`.