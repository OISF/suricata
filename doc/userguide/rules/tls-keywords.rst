SSL/TLS Keywords
================

Suricata comes with several rule keywords to match on various properties of TLS/SSL handshake. Matches are string inclusion matches.

tls_cert_subject
----------------

Match TLS/SSL certificate Subject field.

Examples::

  tls_cert_subject; content:"CN=*.googleusercontent.com"; isdataat:!1,relative;
  tls_cert_subject; content:"google.com"; nocase; pcre:"/google.com$/";

``tls_cert_subject`` is a 'Sticky buffer'.

``tls_cert_subject`` can be used as ``fast_pattern``.

tls_cert_issuer
---------------

Match TLS/SSL certificate Issuer field.

Examples::

  tls_cert_issuer; content:"WoSign"; nocase; isdataat:!1,relative;
  tls_cert_issuer; content:"StartCom"; nocase; pcre:"/StartCom$/";

``tls_cert_issuer`` is a 'Sticky buffer'.

``tls_cert_issuer`` can be used as ``fast_pattern``.

tls_cert_serial
---------------

Match on the serial number in a certificate.

Example::

  alert tls any any -> any any (msg:"match cert serial"; \
    tls_cert_serial; content:"5C:19:B7:B1:32:3B:1C:A1"; sid:200012;)

``tls_cert_serial`` is a 'Sticky buffer'.

``tls_cert_serial`` can be used as ``fast_pattern``.

tls_sni
-------

Match TLS/SSL Server Name Indication field.

Examples::

  tls_sni; content:"oisf.net"; nocase; isdataat:!1,relative;
  tls_sni; content:"oisf.net"; nocase; pcre:"/oisf.net$/";

``tls_sni`` is a 'Sticky buffer'.

``tls_sni`` can be used as ``fast_pattern``.

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

tls.version
-----------

Match on negotiated TLS/SSL version.

Example values: "1.0", "1.1", "1.2"

tls.subject
-----------

Match TLS/SSL certificate Subject field.

example:


::

  tls.subject:"CN=*.googleusercontent.com"

Case sensitve, can't use 'nocase'.

Legacy keyword. ``tls_cert_subject`` is the replacement.

tls.issuerdn
------------

match TLS/SSL certificate IssuerDN field

example:


::

  tls.issuerdn:!"CN=Google-Internet-Authority"

Case sensitve, can't use 'nocase'.

Legacy keyword. ``tls_cert_issuer`` is the replacement.

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

store TLS/SSL certificate on disk

ssl_state
---------

The ``ssl_state`` keyword matches the state of the SSL connection. The possible states
are ``client_hello``, ``server_hello``, ``client_keyx``, ``server_keyx`` and ``unknown``.
You can specify several states with ``|`` (OR) to check for any of the specified states.

Negation support is not available yet, see https://redmine.openinfosecfoundation.org/issues/1231

