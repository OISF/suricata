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

krb5.err_code
-------------

Kerberos error code (integer). This field is matched in  Kerberos error messages only

For a list of error codes, refer to RFC4120 section 7.5.9.

Syntax::

 krb5.err_code:<number>

Signature example::

 alert krb5 any any -> any any (msg:"Kerberos 5 error C_PRINCIPAL_UNKNOWN"; krb5.msg_type:6; sid:6; rev:1;)

krb5.weak_crypto (event)
------------------------

Event raised if the cryptographic parameters selected by the server are weak or
deprecated. For example, using a key size smaller than 128, or using deprecated
ciphers like DES.

This event can be disabled by setting the configuration option
``app-layer.protocols.krb5.warn-weak-crypto`` to false.

Syntax::

  app-layer-event:krb5.weak_crypto

Signature example::

 alert krb5 any any -> any any (msg:"SURICATA Kerberos 5 weak cryptographic parameters"; flow:to_client; app-layer-event:krb5.weak_crypto; classtype:protocol-command-decode; sid:2226001; rev:1;)

krb5.malformed_data (event)
---------------------------

Event raised in case of a protocol decoding error

Syntax::

  app-layer-event:krb5.malformed_data
