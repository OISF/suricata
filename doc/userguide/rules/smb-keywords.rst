SMB Keywords
==============

SMB keywords used in both SMB1 and SMB2 protocols.

smb.named_pipe
--------------

Match on SMB named pipe in tree connect.

Examples::

  smb.named_pipe; content:"IPC"; endswith;
  smb.named_pipe; content:"strange"; nocase; pcre:"/really$/";

``smb.named_pipe`` is a 'sticky buffer'.

``smb.named_pipe`` can be used as ``fast_pattern``.

smb.share
---------

Match on SMB share name in tree connect.

Examples::

  smb.share; content:"shared"; endswith;
  smb.share; content:"strange"; nocase; pcre:"/really$/";

``smb.share`` is a 'sticky buffer'.

``smb.share`` can be used as ``fast_pattern``.

smb.ntlmssp_user
----------------

Match on SMB ntlmssp user in session setup.

Examples::

  smb.ntlmssp_user; content:"doe"; endswith;
  smb.ntlmssp_user; content:"doe"; nocase; pcre:"/j(ohn|ane).*doe$/";

``smb.ntlmssp_user`` is a 'sticky buffer'.

``smb.ntlmssp_user`` can be used as ``fast_pattern``.

smb.ntlmssp_domain
------------------

Match on SMB ntlmssp domain in session setup.

Examples::

  smb.ntlmssp_domain; content:"home"; endswith;
  smb.ntlmssp_domain; content:"home"; nocase; pcre:"/home(sweet)*$/";

``smb.ntlmssp_domain`` is a 'sticky buffer'.

``smb.ntlmssp_domain`` can be used as ``fast_pattern``.
