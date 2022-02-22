**************
Frame Keywords
**************

Overview
========

Frame support is introduced with Suricata 7.0. `Frame` is a generic term that can represent any unit of network data one is interested in. Frames work as "stream annotations", meaning that the engine is able to know what type of record exists at a specific offset in the stream.

Consider a rule like::

    alert smb ... flow:to_server; frame:smb1.data; content:"some smb 1 issue";

This rule will only inspect the data portion of SMB1 frames. It will not affect
any other protocol, and it won't need special patterns to "search" for the
SMB1 frame in the raw stream.

This means that one can write rules to match on more specialized types, making rule writing less tedious and enhancing rules performance - this is especially true if a ruleset has all rules that could use frames converted to this new keyword.

Frame keywords will work for application layer protocols that have frame support added.
As such, the list of available frame keywords vary in a per-protocol basis.

Currently, protocols that support frame keywords are:

- `http`_
- `sip`_
- `smb`_
- `telnet`_
- `tls`_

We have work in progress for supporting ``dcerpc``, ``dns``, ``nfs`` and ``pgsql``, and for the Suricata 7.0 release we want to offer frame support for all parsers.

Examples:

- tls.pdu
- smb.smb2.hdr
- smb.smb3.data

Naming conventions:

- hdr: header (only present in case of successfully parsed records)
- data: payload (only present in case of successfully parsed records)
- pdu: the whole record, for the given app-layer protocol. Always created, even if we have a malformed record.

Frame rule keywords act as sticky buffers and as such they can be combined with any of the content modifier keywords, such as many of the described for `payload <https://suricata.readthedocs.io/en/latest/rules/payload-keywords.html?#payload-keywords>`_.

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

This means that these two rules are equivalent::

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

Frame keywords for SIP
======================
.. _sip:

The following keywords are available for SIP. ``pdu`` frames are always created, while the others will only be seen for valid records:

- pdu (always created)
- request_line
- response_line
- request_headers
- response_headers
- request_body
- response_body

Example rules::

    alert sip any any -> any any (flow:to_server; frame:pdu; content:"REGISTER"; startswith; sid:1;)
    alert sip any any -> any any (flow:to_server; frame:pdu; content:"INVITE sip"; startswith; sid:2;)
    alert sip any any -> any any (flow:to_client; frame:pdu; content:"SIP/2.0 200 OK|0D 0A|"; startswith; sid:3;)
    alert sip any any -> any any (flow:to_server; frame:request.line; content:"REGISTER"; startswith; sid:4;)
    alert sip any any -> any any (flow:to_server; frame:request.line; content:"SIP/2.0|0D 0A|"; endswith; sid:5;)
    alert sip any any -> any any (flow:to_server; frame:request.headers; content:"Via:"; startswith; sid:6;)
    alert sip any any -> any any (flow:to_server; frame:request.headers; content:"Via:"; startswith; content:"229|0d 0a|"; endswith; sid:7;)
    alert sip any any -> any any (flow:to_client; frame:response.headers; content:"Via:"; startswith; sid:8;)
    alert sip any any -> any any (flow:to_client; frame:response.headers; content:"Via:"; startswith; content:"Content-Length: 0|0d 0a|"; endswith; sid:9;)
    alert sip any any -> any any (flow:to_server; frame:request.body; content:"v=0"; startswith; sid:10;)

Frame keywords for SMB
======================
.. _smb:

Except for the ``pdu`` frame, SMB frames are created for valid SMB records. The available keywords are the same, for all versions (nbss, smb1, smb2 or smb3):

- pdu (always created)
- hdr
- data

Example rules::

    alert smb any any -> any any (msg:"SMB data frame keyword"; flow:established; frame:smb1.data; content:"|0c|"; startswith; sid:1; rev:1;)
    alert smb any any -> any any (flow:to_server; frame:smb2.pdu; content:"|FE|SMB"; startswith; sid:2;)
    alert smb any any -> any any (flow:to_server; frame:smb2.hdr; content:"|FE|SMB"; startswith; sid:3;)
    alert smb any any -> any any (flow:to_client; frame:smb2.pdu; content:"|FE|SMB"; startswith; sid:4;)
    alert smb any any -> any any (flow:to_client; frame:smb2.hdr; content:"|FE|SMB"; startswith; sid:5;)
    alert smb any any -> any any (flow:to_client; frame:smb2.data; content:"|FE|SMB"; startswith; sid:6;)
    alert smb any any -> any any (flow:to_client; frame:smb2.data; content:!"|FE|SMB"; startswith; sid:7;)

Frame keywords for Telnet
=========================
.. _telnet:

Available keywords:

- pdu (always created)
- ctl
- data

Example rules::

    alert telnet any any -> any any (flow:to_server; frame:data; content:"/sbin/ping www.yahoo.com"; sid:1;) 

Frame keywords for TLS
======================
.. _tls:

The available keywords vary per version:

TLS
---

- pdu (always created)
- hdr
- data
- alert
- heartbeat

SSL2
----

- ssl2.pdu (always created)
- ssl2.hdr

Example rules::

    alert tls any any -> any any (flow:to_client; frame:tls.pdu; content:"|17 03 03|"; startswith; sid:1;)
    alert tls any any -> any any (flow:to_server; frame:tls.pdu; content:"|17 03 03|"; startswith; sid:2;)
    alert tls any any -> any any (msg:"TLS Change cipher spec"; flow:to_server; frame:tls.hdr; content:"|14|"; startswith; sid:3;)
    alert tls any any -> any any (msg:"TLS Client Hello - hdr frame"; flow:to_server; frame:tls.hdr; content:"|16 03 01|"; startswith; sid:4;)

