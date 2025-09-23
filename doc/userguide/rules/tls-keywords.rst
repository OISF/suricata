.. _TLS Rule Keywords:

SSL/TLS Keywords
================

Suricata comes with several rule keywords to match on various properties of TLS/SSL handshake. Matches are string inclusion matches.

tls.cert_subject
----------------

Match TLS/SSL certificate Subject field.

Examples::

  tls.cert_subject; content:"CN=*.googleusercontent.com"; isdataat:!1,relative;
  tls.cert_subject; content:"google.com"; nocase; pcre:"/google\.com$/";

``tls.cert_subject`` is a 'sticky buffer'.

``tls.cert_subject`` can be used as ``fast_pattern``.

``tls.cert_subject`` supports multiple buffer matching, see :doc:`multi-buffer-matching`.

tls.subject
~~~~~~~~~~~

Legacy keyword to match TLS/SSL certificate Subject field.

example:

::

  tls.subject:"CN=*.googleusercontent.com"

Case sensitive, can't use 'nocase', or other modifiers.

**Note:** ``tls.cert_subject`` replaces the following legacy keywords: ``tls_cert_subject`` and ``tls.subject``. 
It's recommended that rules be converted to use the new one.

tls.cert_issuer
---------------

Match TLS/SSL certificate Issuer field.

Examples::

  tls.cert_issuer; content:"WoSign"; nocase; isdataat:!1,relative;
  tls.cert_issuer; content:"StartCom"; nocase; pcre:"/StartCom$/";

``tls.cert_issuer`` is a 'sticky buffer'.

``tls.cert_issuer`` can be used as ``fast_pattern``.

tls.issuerdn
~~~~~~~~~~~~

Legacy keyword to match TLS/SSL certificate IssuerDN field

example:

::

  tls.issuerdn:!"CN=Google-Internet-Authority"

Case sensitive, can't use 'nocase', or other modifiers.

**Note:** ``tls.cert_issuer`` replaces the following legacy keywords: ``tls_cert_issuer`` and ``tls.issuerdn``. 
It's recommended that rules be converted to use the new one.

tls.cert_serial
---------------

Match on the serial number in a certificate.

Example::

  alert tls any any -> any any (msg:"match cert serial"; \
    tls.cert_serial; content:"5C:19:B7:B1:32:3B:1C:A1"; sid:200012;)

``tls.cert_serial`` is a 'sticky buffer'.

``tls.cert_serial`` can be used as ``fast_pattern``.

``tls.cert_serial`` replaces the previous keyword name: ``tls_cert_serial``. You may continue
to use the previous name, but it's recommended that rules be converted to use
the new name.

tls.cert_fingerprint
--------------------

Match on the SHA-1 fingerprint of the certificate.

Example::

  alert tls any any -> any any (msg:"match cert fingerprint"; \
    tls.cert_fingerprint; \
    content:"4a:a3:66:76:82:cb:6b:23:bb:c3:58:47:23:a4:63:a7:78:a4:a1:18"; \
    sid:200023;)

``tls.cert_fingerprint`` is a 'sticky buffer'.

``tls.cert_fingerprint`` can be used as ``fast_pattern``.

``tls.cert_fingerprint`` replaces the previous keyword name: ``tls_cert_fingerprint`` may continue
to use the previous name, but it's recommended that rules be converted to use
the new name.

tls.sni
-------

Match TLS/SSL Server Name Indication field.

Examples::

  tls.sni; content:"oisf.net"; nocase; isdataat:!1,relative;
  tls.sni; content:"oisf.net"; nocase; pcre:"/oisf.net$/";

``tls.sni`` is a 'sticky buffer'.

``tls.sni`` can be used as ``fast_pattern``.

``tls.sni`` replaces the previous keyword name: ``tls_sni``. You may continue
to use the previous name, but it's recommended that rules be converted to use
the new name.

tls.subjectaltname
------------------

Match TLS/SSL Subject Alternative Name field.

Examples::

  tls.subjectaltname; content:"|73 75 72 69 63 61 74 61 2e 69 6f|";

``tls.subjectaltname`` is a 'sticky buffer'.

``tls.subjectaltname`` can be used as ``fast_pattern``.

``tls.subjectaltname`` supports multiple buffer matching, see :doc:`multi-buffer-matching`.

tls_cert_notbefore
------------------

Match on the NotBefore field in a certificate.

Example::

  alert tls any any -> any any (msg:"match cert NotBefore"; \
    tls_cert_notbefore:1998-05-01<>2008-05-01; sid:200005;)

tls_cert_notafter
-----------------

Match on the NotAfter field in a certificate.

Example::

  alert tls any any -> any any (msg:"match cert NotAfter"; \
    tls_cert_notafter:>2015; sid:200006;)

tls_cert_expired
----------------

Match returns true if certificate is expired. It evaluates the validity date
from the certificate.

Usage::

  tls_cert_expired;

tls_cert_valid
--------------

Match returns true if certificate is not expired. It only evaluates the
validity date. It does *not* do cert chain validation. It is the opposite
of ``tls_cert_expired``.

Usage::

  tls_cert_valid;

tls.certs
---------

Do a "raw" match on each of the certificates in the TLS certificate chain.

Example::

  alert tls any any -> any any (msg:"match bytes in TLS cert"; tls.certs; \
    content:"|06 09 2a 86|"; sid:200070;)

``tls.certs`` is a 'sticky buffer'.

``tls.certs`` can be used as ``fast_pattern``.

``tls.certs`` supports multiple buffer matching, see :doc:`multi-buffer-matching`.

tls.version
-----------

Match on negotiated TLS/SSL version.

Supported values: "1.0", "1.1", "1.2", "1.3"

It is also possible to match versions using a hex string.

Examples::

  tls.version:1.2;
  tls.version:0x7f12;

The first example matches TLSv1.2, whilst the last example matches TLSv1.3
draft 16.

ssl_version
-----------

Match version of SSL/TLS record.

Supported values "sslv2", "sslv3", "tls1.0", "tls1.1", "tls1.2", "tls1.3"

Example::

  alert tls any any -> any any (msg:"match TLSv1.2"; \
    ssl_version:tls1.2; sid:200030;)

It is also possible to match on several versions at the same time.

Example::

  alert tls any any -> any any (msg:"match SSLv2 and SSLv3"; \
    ssl_version:sslv2,sslv3; sid:200031;)

tls.fingerprint
---------------

match TLS/SSL certificate SHA1 fingerprint

example:


::

  tls.fingerprint:!"f3:40:21:48:70:2c:31:bc:b5:aa:22:ad:63:d6:bc:2e:b3:46:e2:5a"

Case sensitive, can't use 'nocase'.

The tls.fingerprint buffer is lower case so you must use lower case letters for this to match.

tls.store
---------

store TLS/SSL certificate on disk.
The location can be specified in the `output.tls-store.certs-log-dir` parameter of the yaml configuration file, cf :ref:`suricata-yaml-outputs-tls`..

ssl_state
---------

The ``ssl_state`` keyword matches the state of the SSL connection. The possible states
are ``client_hello``, ``server_hello``, ``client_keyx``, ``server_keyx`` and ``unknown``.
You can specify several states with ``|`` (OR) to check for any of the specified states.

tls.random
----------

Matches on the 32 bytes of the TLS random field from the client hello or server hello records.

Example::

  alert tls any any -> any any (msg:"TLS random test"; \
    tls.random; content:"|9b ce 7a 5e 57 5d 77 02 07 c2 9d be 24 01 cc f0 5d cd e1 d2 a5 86 9c 4a 3e ee 38 db 55 1a d9 bc|"; sid: 200074;)

``tls.random`` is a sticky buffer.

tls.random_time
---------------

Matches on the first 4 bytes of the TLS random field from the client hello or server hello records.

Example::

  alert tls any any -> any any (msg:"TLS random_time test"; \
    tls.random_time; content:"|9b ce 7a 5e|"; sid: 200075;)

``tls.random_time`` is a sticky buffer.

tls.random_bytes
----------------

Matches on the last 28 bytes of the TLS random field from the client hello or server hello records.

Example::

  alert tls any any -> any any (msg:"TLS random_bytes test"; \
    tls.random_bytes; content:"|57 5d 77 02 07 c2 9d be 24 01 cc f0 5d cd e1 d2 a5 86 9c 4a 3e ee 38 db 55 1a d9 bc|"; sid: 200076;)

``tls.random_bytes`` is a sticky buffer.

tls.cert_chain_len
------------------

Matches on the TLS certificate chain length.

tls.cert_chain_len uses an :ref:`unsigned 32-bit integer <rules-integer-keywords>`.

tls.cert_chain_len supports `<, >, <>, !` and using an exact value.

Example::

  alert tls any any -> any any (msg:"cert chain exact value"; \
 tls.cert_chain_len:1; classtype:misc-activity; sid:1; rev:1;)

  alert tls any any -> any any (msg:"cert chain less than value"; \
 tls.cert_chain_len:<2; classtype:misc-activity; sid:2; rev:1;)

  alert tls any any -> any any (msg:"cert chain greater than value"; \
 tls.cert_chain_len:>0; classtype:misc-activity; sid:2; rev:1;)

  alert tls any any -> any any (msg:"cert chain greater than less than value";\
 tls.cert_chain_len:0<>2; classtype:misc-activity; sid:3; rev:1;)

  alert tls any any -> any any (msg:"cert chain not value"; \
 tls.cert_chain_len:!2; classtype:misc-activity; sid:4; rev:1;)

tls.alpn
--------

Matches on the ALPN buffers.

Example::

  alert tls any any -> any any (msg:"TLS ALPN test"; \
    tls.alpn; content:"http/1.1"; sid:1;)

``tls.alpn`` is a sticky buffer.

