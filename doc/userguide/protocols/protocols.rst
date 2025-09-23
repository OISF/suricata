.. _Protocols:

Protocols
=========

App-Layer
~~~~~~~~~

HTTP
----

The HTTP protocol parser handles HTTP 0.9, 1.0 and 1.1 support.

Rule Keywords
^^^^^^^^^^^^^

HTTP rule keywords are documented in the rule guide :ref:`HTTP Rule Keywords`.

In addition to these specific keywords, file transactions can be inspected with the :ref:`File Rule Keywords`.

Transactions
^^^^^^^^^^^^

Transactions in the HTTP implementation are `bidirectional`. A request and its response together
form the transaction.


HTTP/2
------

HTTP/2 is generally encrypted on the wire, although it *can* be unencrypted. But it's most likely
this traffic will only be seen after some form of TLS decryption.

Rule Keywords
^^^^^^^^^^^^^

HTTP rule keywords apply to HTTP/2 as well and are documented in the rule guide :ref:`HTTP Rule Keywords`.
HTTP/2 specific rule keywords are documented in the rule guide :ref:`HTTP2 Rule Keywords`.

In addition to these specific keywords, file transactions can be inspected with the :ref:`File Rule Keywords`.

TLS
---

TLS support includes SSLv2 and SSLv3.

Rule Keywords
^^^^^^^^^^^^^

TLS rule keywords are documented in the rule guide :ref:`TLS Rule Keywords`.

In addition to these specific keywords, the traffic can be inspected with the :ref:`JA Rule Keywords`.

Transactions
^^^^^^^^^^^^

The TLS implementation uses a single `bidirectional` transaction for the entire TLS flow. It includes
the TLS handshake and the handling of the encrypted portion the traffic.

DNS
---

Rule Keywords
^^^^^^^^^^^^^

DNS rule keywords are documented in the rule guide :ref:`DNS Rule Keywords`.

Transactions
^^^^^^^^^^^^

Transactions in the DNS implementation are `unidirectional`. A DNS request will form a transaction,
and a response will form its own transaction.

SMB
---

SMB is a complex protocol with many dialects and capabilities. The parser supports SMBv1, SMBv2 and SMBv3.

Rule Keywords
^^^^^^^^^^^^^

SMB rule keywords are documented in the rule guide :ref:`SMB Rule Keywords`.

In addition to these specific keywords, file transactions can be inspected with the :ref:`File Rule Keywords`.

DCERPC over SMB traffic can be inspected using :ref:`DCERPC Rule Keywords`.

Transactions
^^^^^^^^^^^^

Transactions in the SMB implementation are `bidirectional`. There are different types:

 - generic request/response pairs
 - file transfer, this may include many write/read commands and their responses, including
   close commands
 - session setup, including several related commands and their responses
 - DCERPC over SMB, this may include several read/write commands to create a DCERPC transaction
   that has a single DCEPRC request and its matching response


Further Reading
~~~~~~~~~~~~~~~

Description of transactional rules :ref:`Transactional Rules`.

More implementation details can be found in the :ref:`Devguide App-Layer` developer guide section.
