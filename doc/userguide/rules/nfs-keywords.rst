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

nfs_procedure
-------------

This keyword allows to match the nfs procedure by its type (integer).

nfs_procedure uses :ref:`unsigned 32-bit integer <rules-integer-keywords>`.

It is also possible to specify the string values for NFSv3 or NFSv4 procedures.
``nfs_procedure: getattr`` will match like ``nfs_procedure: 1; nfs.version: <4;``
or ``nfs_procedure: 9; nfs.version: >=4;``

Unlike the other keywords, the usage of range is inclusive.

Syntax::

 nfs_procedure:(mode) <number or string>
