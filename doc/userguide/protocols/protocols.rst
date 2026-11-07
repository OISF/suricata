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


NFS
---

The NFS parser supports NFSv2 and NFSv3 over UDP, and NFSv3 and NFSv4 over
TCP. NFSv4 is not supported over UDP (RFC 7530 3.1 requires a reliable
callback channel, so it is TCP only).

NFS over TCP is detected without regard to the port: besides the port based
probing parser, a pattern probe matches the ONC RPC call header (message type
CALL, rpcvers 2) on the to-server stream, and the probe then confirms the NFS
program number, version and procedure. So NFS on a non-default port is parsed
and logged, and ``alert nfs`` rules apply to it, where 8.x left such a flow
undetected. Traffic to the other ONC RPC services (mountd, rpcbind, nlockmgr) is
not claimed: their calls carry a different program number, and replies carry
none, which is why the probe is to-server only.

Known limitation: NFSv2 over TCP is not protocol-detected. The RFCs permit
NFSv2 to run over a TCP transport (record-marked ONC RPC), and the parser
handles such traffic correctly when it reaches the parser (for example via a
port-based or forced protocol match), but the protocol probe only accepts
NFSv3 and NFSv4 on TCP. This is a deliberate limitation: NFSv2 over TCP is
exceedingly rare in practice -- virtually all real-world NFSv2 traffic is
carried over UDP, where it is detected and parsed normally.

Rule Keywords
^^^^^^^^^^^^^

NFS rule keywords are documented in the rule guide :ref:`NFS Rule Keywords`.

In addition to these specific keywords, file transactions can be inspected with
the :ref:`File Rule Keywords`.


Further Reading
~~~~~~~~~~~~~~~

Description of transactional rules :ref:`Transactional Rules`.

More implementation details can be found in the :ref:`Devguide App-Layer` developer guide section.
