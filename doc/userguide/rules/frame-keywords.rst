Frame Keywords
**************

Frame keywords will work for application layer protocols that have frame support added.
As such, the list of available frame keywords vary in a per-protocol basis.

Currently, protocols that support frame keywords are:

- SMB (and its versions)
- HTTP
- Telnet
- TLS

This keyword can then be combined with the `content keyword <https://suricata.readthedocs.io/en/latest/rules/payload-keywords.html#content>`_ for detection. 

Naming conventions:

- hdr: header
- data: payload

Frame keywords for SMB
======================

SMB frames are created for valid SMB records. The available keywords are the same, for all versions (nbss, smb1, smb2 or smb3):

- pdu
- hdr
- data

Example rules::

    alert smb any any -> any any (flow:to_server; frame:smb2.pdu; content:"|FE|SMB"; startswith; sid:3;)
    alert smb any any -> any any (flow:to_server; frame:smb2.hdr; content:"|FE|SMB"; startswith; sid:4;)
    alert smb any any -> any any (flow:to_server; frame:smb2.data; content:"|FE|SMB"; startswith; sid:5;)

Frame keywords for HTTP
=======================

The following keywords work alone or with ``http1`` (HTTP2 doesn't support the frame keyword yet):
- request
- response

Example rules::

    alert http any any -> any any (flow:to_server; frame:http1.request; content:"GET / HTTP/1.1|0d 0a|Host: www.testmyids.com"; startswith; bsize:81; sid:1;)
    alert http1 any any -> any any (flow:to_client; frame:response; content:"uid=0|28|root|29|"; sid:2;)
    alert http1 any any -> any any (flow:to_server; frame:request; strip_whitespace; content:"GET/HTTP/1.1Host:www.testmyids.com"; startswith; bsize:66; sid:3;)

Frame keywords for Telnet
=========================

- ctl
- data
- pdu

Example rule::

    alert telnet any any -> any any (flow:to_server; frame:data; content:"/sbin/ping www.yahoo.com"; sid:1;) 

Frame keywords for TLS
======================

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

