Kerberos Keywords
=================

krb5.msg_type
-------------

Kerberos message type (integer).

Values are defined in RFC4120. Common values are

* 10 (AS-REQ)
* 11 (AS-REP)
* 12 (TGS-REQ)
* 13 (TGS-REP)
* 14 (AP-REQ)
* 15 (AP-REP)
* 30 (ERROR)

Syntax::

 krb5.msg_type:<number>

Signature example::

 alert krb5 any any -> any any (msg:"Kerberos 5 AS-REQ message"; krb5.msg_type:10; sid:3; rev:1;)
