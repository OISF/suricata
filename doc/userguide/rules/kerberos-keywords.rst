Kerberos Keywords
=================

krb5_msg_type
-------------

This keyword allows to match the Kerberos messages by its type (integer).
It is possible to specify the following values defined in RFC4120:

krb5_msg_type uses :ref:`unsigned 32-bit integer <rules-integer-keywords>`.

See ``suricata --list-keywords=json | jq '."krb5_msg_type".enum_values'``

* 10 (AS-REQ)
* 11 (AS-REP)
* 12 (TGS-REQ)
* 13 (TGS-REP)
* 30 (ERROR)

Syntax::

 krb5_msg_type:(mode) <number or string>

Signature examples::

 alert krb5 any any -> any any (msg:"Kerberos 5 AS-REQ message"; krb5_msg_type:10; sid:3; rev:1;)
 alert krb5 any any -> any any (msg:"Kerberos 5 AS-REP message"; krb5_msg_type:AS_REP; sid:4; rev:1;)
 alert krb5 any any -> any any (msg:"Kerberos 5 TGS-REQ message"; krb5_msg_type:12; sid:5; rev:1;)
 alert krb5 any any -> any any (msg:"Kerberos 5 TGS-REP message"; krb5_msg_type:13; sid:6; rev:1;)
 alert krb5 any any -> any any (msg:"Kerberos 5 not ERROR message"; krb5_msg_type:!30; sid:7; rev:1;)


.. note:: AP-REQ and AP-REP are not currently supported since those messages
          are embedded in other application protocols.


krb5_cname
----------

Kerberos client name, provided in the ticket (for AS-REP and TGS-REP messages)
or in the error message.

If the client name from the Kerberos message is composed of several parts, the
name is compared to each part and the match will succeed if any is identical.

Comparison is case-sensitive.

Syntax::

 krb5_cname; content:"name";

.. container:: example-rule

 alert krb5 any any -> any any (msg:"Kerberos 5 des server name"; krb5_cname; content:"des"; sid:4; rev:1;)

``krb5_cname`` is a 'sticky buffer'.

``krb5_cname`` can be used as ``fast_pattern``.

``krb5.cname`` supports multiple buffer matching, see :doc:`multi-buffer-matching`.

krb5_sname
----------

Kerberos server name, provided in the ticket (for AS-REP and TGS-REP messages)
or in the error message.

If the server name from the Kerberos message is composed of several parts, the
name is compared to each part and the match will succeed if any is identical.

Comparison is case-sensitive.

Syntax::

 krb5_sname; content:"name";

.. container:: example-rule

 alert krb5 any any -> any any (msg:"Kerberos 5 krbtgt server name"; krb5_sname; content:"krbtgt"; sid:5; rev:1;)

``krb5_sname`` is a 'sticky buffer'.

``krb5_sname`` can be used as ``fast_pattern``.

``krb5.sname`` supports multiple buffer matching, see :doc:`multi-buffer-matching`.

krb5_err_code
-------------

Kerberos error code (integer). This field is matched in Kerberos error messages only.

For a list of error codes, refer to RFC4120 section 7.5.9.

krb5_err_code uses :ref:`unsigned 32-bit integer <rules-integer-keywords>`.

Syntax::

 krb5_err_code:<number>

.. container:: example-rule

 alert krb5 any any -> any any (msg:"Kerberos 5 error C_PRINCIPAL_UNKNOWN"; krb5_err_code:6; sid:6; rev:1;)

krb5.weak_encryption (event)
----------------------------

Event raised if the encryption type used for the encrypted part of an AS-REP or
TGS-REP response is weak or deprecated. This event refers to the response's
encrypted part; it does not describe the encryption type of the ticket carried
inside the response.

Use ``krb5.ticket_encryption`` to match the ticket's encryption type.

Syntax::

 app-layer-event:krb5.weak_encryption

.. container:: example-rule

 alert krb5 any any -> any any (msg:"SURICATA Kerberos 5 weak encryption parameters"; flow:to_client; app-layer-event:krb5.weak_encryption; classtype:protocol-command-decode; sid:2226001; rev:1;)

In EVE JSON, the ``krb5.weak_encryption`` event corresponds to the
``weak_encryption`` boolean, while the ticket's encryption status is exposed
separately as ``ticket_weak_encryption``. The latter is an EVE JSON field,
not a rule keyword.

krb5.malformed_data (event)
---------------------------

Event raised in case of a protocol decoding error.

Syntax::

 app-layer-event:krb5.malformed_data

.. container:: example-rule

 alert krb5 any any -> any any (msg:"SURICATA Kerberos 5 malformed request data"; flow:to_server; app-layer-event:krb5.malformed_data; classtype:protocol-command-decode; sid:2226000; rev:1;)

krb5.ticket_encryption
----------------------

Encryption type of the Kerberos ticket carried in an AS-REP or TGS-REP message
(enumeration). This is distinct from the encryption type of the response's
encrypted part, which is reported by the ``krb5.weak_encryption`` event.

For a list of encryption types, refer to RFC3961 section 8. The value 23
(``rc4-hmac``) identifies RC4-HMAC. The ``weak`` selector matches all
encryption types Suricata classifies as weak or deprecated; use an explicit
encryption type when a rule should target a specific algorithm.

Syntax::

 krb5.ticket_encryption: (!)"weak" or (space or comma)-separated list of integer or string values for an encryption type

.. container:: example-rule

 alert krb5 any any -> any any (krb5.ticket_encryption: weak; sid:1;)

.. container:: example-rule

 alert krb5 any any -> any any (krb5.ticket_encryption: 23; sid:2;)

.. container:: example-rule

 alert krb5 any any -> any any (krb5.ticket_encryption: rc4-hmac,rc4-hmac-exp; sid:3;)

The following rule matches TGS-REP messages whose tickets use RC4-HMAC:

.. container:: example-rule

 alert krb5 any any -> any any (msg:"Kerberos TGS-REP with RC4-HMAC encrypted ticket"; krb5_msg_type:TGS_REP; krb5.ticket_encryption:rc4-hmac; sid:1000001; rev:1;)

RC4-HMAC tickets can be relevant during Kerberoasting investigations, but this
match alone does not prove that an attack is taking place. Validate the client,
requested service, environment baseline, and surrounding authentication
activity before treating an alert as malicious.

