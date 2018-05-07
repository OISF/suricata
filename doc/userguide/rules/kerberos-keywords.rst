Kerberos Keywords
=================

krb5_msg_type
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

 krb5_msg_type:<number>

Signature example::

 alert krb5 any any -> any any (msg:"Kerberos 5 AS-REQ message"; krb5_msg_type:10; sid:3; rev:1;)

krb5_cname
----------

Kerberos client name, provided in the ticket (for AS-REQ and TGS-REQ messages).

If the client name from the Kerberos message is composed of several parts, the
name is compared to each part and the match will succeed if any is identical.

Comparison is case-sensitive.

Syntax::

 krb5_cname:[!]<name>

Signature example::

 alert krb5 any any -> any any (msg:"Kerberos 5 des server name"; krb5_cname; content:"des"; sid:4; rev:1;)

``krb5_cname`` is a 'sticky buffer'.

``krb5_cname`` can be used as ``fast_pattern``.

krb5_sname
----------

Kerberos server name, provided in the ticket (for AS-REQ and TGS-REQ messages)
or in the error message.

If the server name from the Kerberos message is composed of several parts, the
name is compared to each part and the match will succeed if any is identical.

Comparison is case-sensitive.

Syntax::

 krb5_sname:[!]<name>

Signature example::

 alert krb5 any any -> any any (msg:"Kerberos 5 krbtgt server name"; krb5_sname; content:"krbtgt"; sid:5; rev:1;)

``krb5_sname`` is a 'sticky buffer'.

``krb5_sname`` can be used as ``fast_pattern``.

krb5_err_code
-------------

Kerberos error code (integer). This field is matched in  Kerberos error messages only

For a list of error codes, refer to RFC4120 section 7.5.9.

Syntax::

 krb5_err_code:<number>

Signature example::

 alert krb5 any any -> any any (msg:"Kerberos 5 error C_PRINCIPAL_UNKNOWN"; krb5_err_code:6; sid:6; rev:1;)
