SIP Keywords
============

The SIP keywords are implemented as sticky buffers and can be used to match on fields in SIP messages.

As described in RFC3261, common header field names can be represented in a short form. 
In such cases, the header name is normalized to its regular form to be matched by its
corresponding sticky buffer.

============================== ==================
Keyword                        Direction
============================== ==================
sip.method                     Request
sip.uri                        Request
sip.request_line               Request
sip.stat_code                  Response
sip.stat_msg                   Response
sip.response_line              Response
sip.protocol                   Both
sip.from                       Both
sip.to                         Both
sip.via                        Both
sip.user_agent                 Both
sip.content_type               Both
sip.content_length             Both
============================== ==================

sip.method
----------

This keyword matches on the method found in a SIP request.

Syntax
~~~~~~

::

  sip.method; content:<method>;

Examples of methods are:

* INVITE
* BYE
* REGISTER
* CANCEL
* ACK
* OPTIONS

Examples
~~~~~~~~

::

  sip.method; content:"INVITE";

sip.uri
-------

This keyword matches on the uri found in a SIP request.

Syntax
~~~~~~

::

  sip.uri; content:<uri>;

Where <uri> is an uri that follows the SIP URI scheme.

Examples
~~~~~~~~

::

  sip.uri; content:"sip:sip.url.org";

sip.request_line
----------------

This keyword forces the whole SIP request line to be inspected.

Syntax
~~~~~~

::

  sip.request_line; content:<request_line>;

Where <request_line> is a partial or full line.

Examples
~~~~~~~~

::

  sip.request_line; content:"REGISTER sip:sip.url.org SIP/2.0"

sip.stat_code
-------------

This keyword matches on the status code found in a SIP response.

Syntax
~~~~~~

::

  sip.stat_code; content:<stat_code>

Where <status_code> belongs to one of the following groups of codes:

* 1xx - Provisional Responses
* 2xx - Successful Responses
* 3xx - Redirection Responses
* 4xx - Client Failure Responses
* 5xx - Server Failure Responses
* 6xx - Global Failure Responses

Examples
~~~~~~~~

::

  sip.stat_code; content:"100";

sip.stat_msg
------------

This keyword matches on the status message found in a SIP response.

Syntax
~~~~~~

::

  sip.stat_msg; content:<stat_msg>

Where <stat_msg> is a reason phrase associated to a status code.

Examples
~~~~~~~~

::

  sip.stat_msg; content:"Trying";

sip.response_line
-----------------

This keyword forces the whole SIP response line to be inspected.

Syntax
~~~~~~

::

  sip.response_line; content:<response_line>;

Where <response_line> is a partial or full line.

Examples
~~~~~~~~

::

  sip.response_line; content:"SIP/2.0 100 OK"

sip.protocol
------------

This keyword matches the protocol field from a SIP request or response line.

If the response line is 'SIP/2.0 100 OK', then this buffer will contain 'SIP/2.0'

Syntax
~~~~~~

::

  sip.protocol; content:<protocol>

Where <protocol> is the SIP protocol version.

Example
~~~~~~~

::

  sip.protocol; content:"SIP/2.0"

sip.from
--------

This keyword matches on the From field that can be present in SIP headers.
It matches both the regular and short forms, though it cannot distinguish between them. 

Syntax
~~~~~~

::

  sip.from; content:<from>

Where <from> is the value of the From header.

Example
~~~~~~~

::

  sip.from; content:"user"

sip.to
------

This keyword matches on the To field that can be present in SIP headers.
It matches both the regular and short forms, though it cannot distinguish between them. 

Syntax
~~~~~~

::

  sip.to; content:<to>

Where <to> is the value of the To header.

Example
~~~~~~~

::

  sip.to; content:"user"

sip.via
--------

This keyword matches on the Via field that can be present in SIP headers.
It matches both the regular and short forms, though it cannot distinguish between them. 

Syntax
~~~~~~

::

  sip.via; content:<via>

Where <via> is the value of the Via header.

Example
~~~~~~~

::

  sip.via; content:"SIP/2.0/UDP"

sip.user_agent
--------------

This keyword matches on the User-Agent field that can be present in SIP headers.

Syntax
~~~~~~

::

  sip.user_agent; content:<user_agent>

Where <user_agent> is the value of the User-Agent header.

Example
~~~~~~~

::

  sip.user_agent; content:"Asterisk"

sip.content_type
----------------

This keyword matches on the Content-Type field that can be present in SIP headers.
It matches both the regular and short forms, though it cannot distinguish between them. 

Syntax
~~~~~~

::

  sip.content_type; content:<content_type>

Where <content_type> is the value of the Content-Type header.

Example
~~~~~~~

::

  sip.content_type; content:"application/sdp"

sip.content_length
------------------

This keyword matches on the Content-Length field that can be present in SIP headers.
It matches both the regular and short forms, though it cannot distinguish between them. 

Syntax
~~~~~~

::

  sip.content_length; content:<content_length>

Where <content_length> is the value of the Content-Length header.

Example
~~~~~~~

::

  sip.content_length; content:"200"
