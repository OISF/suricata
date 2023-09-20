NFS Keywords
============

file.name
---------

The ``file.name`` keyword can be used at the NFS application level. 

Example::

  alert nfs any any -> any any (msg:"nfs layer file.name keyword usage"; \
 file.name; content:"file.txt"; classtype:bad-unknown; sid:1; rev:1;)

For additional information on the ``file.name`` keyword, see :doc:`file-keywords`.