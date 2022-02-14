SMB Keywords
==============

SMB keywords used in both SMB1 and SMB2 protocols.

smb_version
--------------

Used to match the SMB version, that can be 1 or 2.

Example signatures::

  alert smb any any -> any any (msg: "SMB1 version rule"; smb.version: 1; sid: 44;)
  alert smb any any -> any any (msg: "SMB2 version rule"; smb.version: 2; sid: 45;)

