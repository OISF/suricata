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

Match on the name the NFS transaction carries, when known. The name is
learned from LOOKUP and friends and associated with the file handle, so
READ and WRITE transactions on that handle carry it too. It holds the same
bytes as the ``nfs.filename`` field of the NFS event, and it is a name
component, not a path: NFS names a file by handle once the directory walk
is done.

Examples::

  nfs.name; content:"secret.txt"; endswith;
  nfs.name; content:".crypter"; nocase;

``nfs.name`` is a 'sticky buffer'.

``nfs.name`` can be used as ``fast_pattern``.

For a READ or WRITE that opens a file, the generic :doc:`file-keywords`
keyword ``file.name`` matches the same bytes: the file engine records the
name at open. Prefer ``file.name`` there. ``nfs.name`` is the wider of the
two: it also covers the requests that name a file without transferring it
(LOOKUP, RENAME, READDIR, READLINK, SETATTR, COMMIT) and it works when file
store is off. SMB, which this mirrors, registers no name buffer at all
because its names always come with a file, a pipe (``smb.named_pipe``) or a
share (``smb.share``); its file names are matched with ``file.name``.

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

``nfs.handle`` can be used as ``fast_pattern``. The handle is the raw
file handle; the NFS event logs a hash of it as ``nfs.hhash``, which is not
what this buffer matches.

Signature Example:

.. container:: example-rule

  alert nfs any any -> any any (msg:"NFS nfs.handle usage"; \
  :example-rule-options:`nfs.handle; content:"|01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10|";` \
  classtype:bad-unknown; sid:1; rev:1;)
