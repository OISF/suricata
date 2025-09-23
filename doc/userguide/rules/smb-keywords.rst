.. _SMB Rule Keywords:

SMB Keywords
============

.. role:: example-rule-options

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


smb.version
------------

Keyword to match on the SMB version seen in an SMB transaction.

Signature Example:

.. container:: example-rule

  alert smb $HOME_NET any -> any any (msg:"SMBv1 version rule"; \
  :example-rule-options:`smb.version:1;` sid:1;)
  
  alert smb $HOME_NET any -> any any (msg:"SMBv2 version rule"; \
  :example-rule-options:`smb.version:2;` sid:2;)


Matching in transition from SMBv1 to SMBv2
******************************************

In the initial protocol negotiation request, a client supporting SMBv1 and SMBv2 can send an initial SMBv1 request and receive a SMBv2 response from server, indicating that SMBv2 will be used.

This first SMBv2 response made by the server will match as SMBv1, since the entire transaction will be considered a SMBv1 transaction.

Will ``smb.version`` match SMBv3 traffic?
*****************************************

Yes, it will match SMBv3 messages using `smb.version:2;`, which will match SMBv2 and SMBv3, since they use the same version identifier in the SMB header.

This keyword will use the Protocol ID specified in SMB header to determine the version. Here is a summary of the Protocol ID codes:

- 0xffSMB is SMBv1 `header <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/3c0848a6-efe9-47c2-b57a-f7e8217150b9>`_
- 0xfeSMB is SMBv2 `normal header <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5cd64522-60b3-4f3e-a157-fe66f1228052>`_ (can be `sync <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fb188936-5050-48d3-b350-dc43059638a4>`_ or `async <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ea4560b7-90da-4803-82b5-344754b92a79>`_)
- 0xfdSMB is SMBv2 `transform header <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d6ce2327-a4c9-4793-be66-7b5bad2175fa>`_. This is only valid for the SMB 3.x dialect family.
- 0xfcSMB is SMBv2 `transform compression header <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d6ce2327-a4c9-4793-be66-7b5bad2175fa>`_ (can be `chained <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/aa880fe8-ebed-4409-a474-ec6e0ca0dbcb>`_ or `unchained <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/793db6bb-25b4-4469-be49-a8d7045ba3a6>`_). These ones require the use of the 3.1.1 dialect.

The Protocol ID in the header distinguishes only SMBv1 and SMBv2 since they are completely different protocols with entirely
different message formats, types and implementations.

On the other hand, SMBv3 is more like an extension of SMBv2. When using SMBv2 we can select one of the following dialects for the conversation between client and server:

- 2.0.2
- 2.1
- 3.0
- 3.0.2
- 3.1.1

We say we are using SMBv3 when we select a 3.x dialect for the conversation, so you can use SMB 3.0, SMB 3.0.2 or SMB 3.1.1. The higher you choose, the more capabilities you have, but the message syntax and message command number remains the same.

SMB version and dialect are separate components. In the case of SMBv3 for instance, the SMB version will be 2 but the dialect will be 3.x. Dialect specification is not available currently via keyword.

file.name
---------

The ``file.name`` keyword can be used at the SMB application level. 

Signature Example:

.. container:: example-rule

  alert smb any any -> any any (msg:"SMB file.name usage"; \
  :example-rule-options:`file.name; content:"file.txt";` \
  classtype:bad-unknown; sid:1; rev:1;)

For additional information on the ``file.name`` keyword, see :doc:`file-keywords`.
