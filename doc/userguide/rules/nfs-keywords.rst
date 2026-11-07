.. _NFS Rule Keywords:

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

See ``suricata --list-keywords=json | jq '."nfs_procedure".enum_values'``
to have the list of all the string values for NFS v2, v3 and v4 procedures.

Unlike the other keywords, the usage of range is inclusive.

Syntax::

 nfs_procedure:(mode) <number or string>

nfs.name
--------

This keyword allows to match the file name of the NFS transaction,
when known. The name is learned from LOOKUP (and similar) requests
and associated with the file handle; READ and WRITE transactions on
that handle carry the name as well.

It is a sticky buffer: use ``content`` (and other content keywords)
to match on it.

Signature Example:

.. container:: example-rule

  alert nfs any any -> any any (msg:"NFS nfs.name usage"; \
  :example-rule-options:`nfs.name; content:"secret.txt";` \
  classtype:bad-unknown; sid:1; rev:1;)

nfs.handle
----------

This keyword allows to match the file handle of the NFS transaction,
when known. File handles are binary and server-specific, so match
them with hex escapes.

It is a sticky buffer: use ``content`` with hex escapes to match on
it.

Signature Example:

.. container:: example-rule

  alert nfs any any -> any any (msg:"NFS nfs.handle usage"; \
  :example-rule-options:`nfs.handle; content:"|01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10|";` \
  classtype:bad-unknown; sid:1; rev:1;)
