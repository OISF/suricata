NFS Keywords
============

.. role:: example-rule-options

file.name
---------

The ``file.name`` keyword can be used at the NFS application level. 

Signature Example:

.. container:: example-rule

  alert nfs any any -> any any (msg:"NFS file.name usage"; \
  :example-rule-options:`file.name; content:"file.txt";` \
  classtype:bad-unknown; sid:1; rev:1;)

For additional information on the ``file.name`` keyword, see :doc:`file-keywords`.