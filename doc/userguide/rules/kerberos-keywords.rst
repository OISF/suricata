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

 krb5_cname; content:"name";

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

 krb5_sname; content:"name";

Signature example::

 alert krb5 any any -> any any (msg:"Kerberos 5 krbtgt server name"; krb5_sname; content:"krbtgt"; sid:5; rev:1;)

``krb5_sname`` is a 'sticky buffer'.

``krb5_sname`` can be used as ``fast_pattern``.

krb5_err_code
-------------

Kerberos error code (integer). This field is matched in Kerberos error messages only.

For a list of error codes, refer to RFC4120 section 7.5.9.

Syntax::

 krb5_err_code:<number>

Signature example::

 alert krb5 any any -> any any (msg:"Kerberos 5 error C_PRINCIPAL_UNKNOWN"; krb5_err_code:6; sid:6; rev:1;)

krb5.weak_encryption (event)
----------------------------

Event raised if the encryption parameters selected by the server are weak or
deprecated. For example, using a key size smaller than 128, or using deprecated
ciphers like DES.

Syntax::

 app-layer-event:krb5.weak_encryption

Signature example::

 alert krb5 any any -> any any (msg:"SURICATA Kerberos 5 weak encryption parameters"; flow:to_client; app-layer-event:krb5.weak_encryption; classtype:protocol-command-decode; sid:2226001; rev:1;)

krb5.malformed_data (event)
---------------------------

Event raised in case of a protocol decoding error.

Syntax::

 app-layer-event:krb5.malformed_data

Signature example::

 alert krb5 any any -> any any (msg:"SURICATA Kerberos 5 malformed request data"; flow:to_server; app-layer-event:krb5.malformed_data; classtype:protocol-command-decode; sid:2226000; rev:1;)

krb5.ticket_encryption
----------------------

Kerberos ticket encryption (enumeration).

For a list of encryption types, refer to RFC3961 section 8.

Syntax::

 krb5.ticket_encryption: (!)"weak" or (space or comma)-separated list of integer or string values for an encryption type

Signature example::

 alert krb5 any any -> any any (krb5.ticket_encryption: weak; sid:1;)
 alert krb5 any any -> any any (krb5.ticket_encryption: 23; sid:2;)
 alert krb5 any any -> any any (krb5.ticket_encryption: rc4-hmac,rc4-hmac-exp; sid:3;)