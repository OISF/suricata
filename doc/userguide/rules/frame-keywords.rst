**************
Frame Keywords
**************

Overview
========

Consider a rule like::

    alert smb ... flow:to_server; frame:smb1.data; content:"some smb 1 issue";

This rule will only inspect the data portion of SMB1 frames. It will not affect
any other protocol, and it won't need special patterns to "search" for the
SMB1 frame in the raw stream.

Frame keywords will work for application layer protocols that have frame support added.
As such, the list of available frame keywords vary in a per-protocol basis.

Currently, protocols that support frame keywords are:

- `http`_
- `smb`_
- `telnet`_
- `tls`_

Examples:

- tls.pdu
- smb.smb2.hdr
- smb.smb3.data

Naming conventions:

- hdr: header
- data: payload

This keyword can then be combined with the `content keyword <https://suricata.readthedocs.io/en/latest/rules/payload-keywords.html#content>`_ for detection. 

Usage
-----

This keyword takes an argument to specify the per protocol frame type::

    alert <app proto name> ... frame:<specific frame name>

Or it can specify both in the keyword::

    alert tcp ... frame:<app proto name>.<specific frame name>

The latter is useful in some cases like http, where "http" applies to
both HTTP and HTTP/2::

    alert http ... frame:http1.request;
    alert http1 ... frame:request;

This mean that these two rules are equivalent::

    alert tcp ... frame:tls.pdu;
    alert tls ... frame:pdu;

Frame keywords for HTTP
=======================

.. _http:

The following keywords work alone or with ``http1`` (HTTP2 doesn't support the frame keyword yet):

- request
- response

Example rules::

    alert http any any -> any any (flow:to_server; frame:http1.request; content:"GET / HTTP/1.1|0d 0a|Host: www.testmyids.com"; startswith; bsize:81; sid:1;)
    alert http1 any any -> any any (flow:to_client; frame:response; content:"uid=0|28|root|29|"; sid:2;)
    alert http1 any any -> any any (flow:to_server; frame:request; strip_whitespace; content:"GET/HTTP/1.1Host:www.testmyids.com"; startswith; bsize:66; sid:3;)

Frame keywords for SMB
======================

.. _smb:

SMB frames are created for valid SMB records. The available keywords are the same, for all versions (nbss, smb1, smb2 or smb3):

- pdu
- hdr
- data

Example rules::

    alert smb any any -> any any (flow:to_server; frame:smb2.pdu; content:"|FE|SMB"; startswith; sid:3;)
    alert smb any any -> any any (flow:to_server; frame:smb2.hdr; content:"|FE|SMB"; startswith; sid:4;)
    alert smb any any -> any any (flow:to_server; frame:smb2.data; cont:ent:"|FE|SMB"; startswith; sid:5;)

Frame keywords for Telnet
=========================

.. _telnet:

- ctl
- data
- pdu

Example rules::

    alert telnet any any -> any any (flow:to_server; frame:data; content:"/sbin/ping www.yahoo.com"; sid:1;) 

Frame keywords for TLS
======================

.. _tls:

TLS
---

- pdu
- hdr
- data
- alert
- heartbeat

SSL2
----

- ssl2.hdr
- ssl2.pdu

Example rules::

    alert tls any any -> any any (flow:to_client; frame:tls.pdu; content:"|17 03 03|"; startswith; sid:1;)
    alert tls any any -> any any (flow:to_server; frame:tls.pdu; content:"|17 03 03|"; startswith; sid:2;)

