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

krb5.cname
----------

Kerberos client name, provided in the ticket (for AS-REQ and TGS-REQ messages).

If the client name from the Kerberos message is composed of several parts, the
name is compared to each part and the match will succeed if any is identical.

Comparison is case-sensitive.

Syntax::

 krb5.cname:[!]<name>

Signature example::

 alert krb5 any any -> any any (msg:"Kerberos 5 des server name"; krb5.cname:des; sid:4; rev:1;)

krb5.sname
----------

Kerberos server name, provided in the ticket (for AS-REQ and TGS-REQ messages)
or in the error message.

If the server name from the Kerberos message is composed of several parts, the
name is compared to each part and the match will succeed if any is identical.

Comparison is case-sensitive.

Syntax::

 krb5.sname:[!]<name>

Signature example::

 alert krb5 any any -> any any (msg:"Kerberos 5 krbtgt server name"; krb5.sname:krbtgt; sid:5; rev:1;)
