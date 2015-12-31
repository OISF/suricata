SSL/TLS Keywords
============

Suricata comes with several rule keywords to match on various properties of TLS/SSL handshake. Matches are string inclusion matches.

tls.version
-----------

Match on negotiated TLS/SSL version.

Example values: "1.0", "1.1", "1.2"

Support added in Suricata version 1.3.

tls.subject
-----------

Match TLS/SSL certificate Subject field.

example:


::

  tls.subject:"CN=*.googleusercontent.com"

Support added in Suricata version 1.3.

Case sensitve, can't use 'nocase'.

tls.issuerdn
------------

match TLS/SSL certificate IssuerDN field

example:


::

  tls.issuerdn:!"CN=Google-Internet-Authority"

Support added in Suricata version 1.3.

Case sensitve, can't use 'nocase'.

tls.fingerprint
---------------

match TLS/SSL certificate SHA1 fingerprint

example:


::

  tls.fingerprint:!"f3:40:21:48:70:2c:31:bc:b5:aa:22:ad:63:d6:bc:2e:b3:46:e2:5a"

Support added in Suricata version 1.4.

Case sensitive, can't use 'nocase'.

The tls.fingerprint buffer is lower case so you must use lower case letters for this to match.

tls.store
---------

store TLS/SSL certificate on disk

Support added in Suricata version 1.4.

ssl_state
---------

The ``ssl_state`` keyword matches the state of the SSL connection. The possible states
are ``client_hello``, ``server_hello``, ``client_keyx``, ``server_keyx`` and ``unknown``.
You can specify several states with ``|`` (OR) to check for any of the specified states.

Negation support is not available yet, see https://redmine.openinfosecfoundation.org/issues/1231
