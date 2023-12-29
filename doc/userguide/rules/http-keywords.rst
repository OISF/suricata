HTTP Keywords
=============

.. role:: example-rule-action
.. role:: example-rule-header
.. role:: example-rule-options
.. role:: example-rule-emphasis

Using the HTTP specific sticky buffers (see :ref:`rules-modifiers`) provides a
way to efficiently inspect the specific fields of HTTP protocol communications.
After specifying a sticky buffer in a rule it should be followed by one or
more :doc:`payload-keywords`.

HTTP Primer
-----------
HTTP is considered a client-server or request-response protocol. A client
requests resources from a server and a server responds to the request.

In versions of HTTP prior to version 2 a client request could look like:

Example HTTP Request::

  GET /index.html HTTP/1.1
  User-Agent: Mozilla/5.0
  Host: suricata.io

Example signature that would alert on the above request.

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Request Example"; \
  flow:established,to_server; :example-rule-options:`http.method; \
  content:"GET"; http.uri; content:"/index.html"; bsize:11; http.protocol; \
  content:"HTTP/1.1"; bsize:8; http.user_agent; content:"Mozilla/5.0"; bsize:11; \
  http.host; content:"suricata.io"; bsize:11;` classtype:bad-unknown; sid:25; rev:1;)

In versions of HTTP prior to version 2 a server response could look like:

Example HTTP Response::

  HTTP/1.1 200 OK
  Content-Type: text/html
  Content-Length: 258
  Date: Thu, 14 Dec 2023 20:22:41 GMT
  Server: nginx/0.8.54
  Connection: Close

Example signature that would alert on the above response.

.. container:: example-rule

  alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP Stat Code Example"; \
  flow:established,to_client; :example-rule-options:`http.stat_code; \
  content:"200"; bsize:8; http.content_type; content:"text/html"; bsize:9;` \
  classtype:bad-unknown; sid:30; rev:1;)

Request Keywords:
 * :ref:`http.uri`
 * :ref:`http.uri.raw`
 * :ref:`http.method`
 * :ref:`http.request_line`
 * :ref:`http.request_body`
 * :ref:`http.user_agent`
 * :ref:`http.host`
 * :ref:`http.accept`
 * :ref:`http.accept_lang`
 * :ref:`http.accept_enc`
 * :ref:`http.referer`
 * :ref:`file.name`

Response Keywords:
 * :ref:`http.stat_msg`
 * :ref:`http.stat_code`
 * :ref:`http.response_line`
 * :ref:`http.response_body`
 * :ref:`http.server`
 * :ref:`http.location`

Request or Response Keywords:
 * :ref:`file.data`
 * :ref:`http.content_type`
 * :ref:`http.content_len`
 * :ref:`http.start`
 * :ref:`http.protocol`
 * :ref:`http.header_names`
 * :ref:`http.header`
 * :ref:`http.cookie`

Although cookies are sent in an HTTP header, you can not match on them
with the ``http.header`` keyword. Cookies are matched with their own
keyword, namely ``http.cookie``.

Each part of the table belongs to a so-called *buffer*. The HTTP
method belongs to the method buffer, HTTP headers to the header buffer
etc. A buffer is a specific portion of the request or response that
Suricata extracts in memory for inspection.

All previous described keywords can be used in combination with a
buffer in a signature. The keywords ``distance`` and ``within`` are
relative modifiers, so they may only be used within the same
buffer. You can not relate content matches against different buffers
with relative modifiers.

.. _http.method:

http.method
-----------

The ``http.method`` keyword matches on the method/verb used in an HTTP request.
HTTP request methods can be any of the following:

* GET
* POST
* HEAD
* OPTIONS
* PUT
* DELETE
* TRACE
* CONNECT
* PATCH

It is possible to use any of the :doc:`payload-keywords` with the ``http.method`` keyword.

Example HTTP Request::

  GET /index.html HTTP/1.1
  User-Agent: Mozilla/5.0
  Host: suricata.io

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Request Example"; \
  flow:established,to_server; :example-rule-options:`http.method; \
  content:"GET";` classtype:bad-unknown; sid:2; rev:1;)

.. _rules-http-uri-normalization:

.. _http.uri:

http.uri 
--------

Matching on the HTTP URI buffer has two options in Suricata, the ``http.uri``
and the ``http.uri.raw`` sticky buffers.

It is possible to use any of the :doc:`payload-keywords` with the ``http.uri``
keywords.

The ``http.uri`` keyword normalizes the URI buffer. For example, if a URI has two
leading ``//``, Suricata will normalize the URI to a single leading ``/``.

Normalization Example::

  GET //index.html HTTP/1.1
  User-Agent: Mozilla/5.0
  Host: suricata.io

In this case :example-rule-emphasis:`//index.html` would be normalized to 
:example-rule-emphasis:`/index.html`.

Normalized HTTP Request Example::

  GET /index.html HTTP/1.1
  User-Agent: Mozilla/5.0
  Host: suricata.io

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP URI Example"; \
  flow:established,to_server; :example-rule-options:`http.uri; \
  content:"/index.html";` bsize:11; classtype:bad-unknown; sid:3; rev:1;)

.. _http.uri.raw:

http.uri.raw
------------

The ``http.uri.raw`` buffer matches on HTTP URI content but does not
have any normalization performed on the buffer contents.
(see :ref:`rules-http-uri-normalization`)

Abnormal HTTP Request Example::

  GET //index.html HTTP/1.1
  User-Agent: Mozilla/5.0
  Host: suricata.io

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP URI Raw Example"; \
  flow:established,to_server; :example-rule-options:`http.uri.raw; \
  content:"//index.html";` bsize:12; classtype:bad-unknown; sid:4; rev:1;)

.. note:: The ``http.uri.raw`` keyword/buffer does not allow for spaces.

Example Request::

  GET /example spaces HTTP/1.1
  User-Agent: Mozilla/5.0
  Host: suricata.io

``http.uri.raw`` would be populated with :example-rule-header:`/example`

:ref:`http.protocol` would be populated with :example-rule-header:`spaces HTTP/1.1`

Reference: `https://redmine.openinfosecfoundation.org/issues/2881 <https://redmine.openinfosecfoundation.org/issues/2881>`_

.. _urilen:

urilen
------

The ``urilen`` keyword is used to match on the length of the request
URI. It is possible to use the ``<`` and ``>`` operators, which
indicate respectively *smaller than* and *larger than*.

urilen uses an :ref:`unsigned 64-bit integer <rules-integer-keywords>`.

The format of ``urilen`` is::

  urilen:3;

Other possibilities are::

  urilen:1;
  urilen:>1;
  urilen:<10;
  urilen:10<>20;	(bigger than 10, smaller than 20)

Example:


Example of ``urilen`` in a signature:

.. container:: example-rule

    alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET TROJAN Possible Vundo Trojan Variant reporting to Controller"; flow:established,to_server; content:"POST "; depth:5; uricontent:"/frame.html?"; :example-rule-emphasis:`urilen: > 80;` classtype:trojan-activity; reference:url,doc.emergingthreats.net/2009173; reference:url,www.emergingthreats.net/cgi-bin/cvsweb.cgi/sigs/VIRUS/TROJAN_Vundo; sid:2009173; rev:2;)

You can also append ``norm`` or ``raw`` to define what sort of buffer you want
to use (normalized or raw buffer).

.. _http.protocol:

http.protocol
-------------

The ``http.protocol`` inspects the protocol field from the HTTP request or
response line. If the request line is 'GET / HTTP/1.0\r\n', then this buffer
will contain 'HTTP/1.0'.

Example::

    alert http any any -> any any (flow:to_server; http.protocol; content:"HTTP/1.0"; sid:1;)

``http.protocol`` replaces the previous keyword name: ```http_protocol``. You may continue to use the previous name, but it's recommended that rules be converted to use the new name.

Example::

    alert http any any -> any any (flow:to_server; http.protocol; content:"HTTP/1.0"; sid:1;)

.. _http.request_line:

http.request_line
-----------------

The ``http.request_line`` forces the whole HTTP request line to be inspected.

Example::

    alert http any any -> any any (http.request_line; content:"GET / HTTP/1.0"; sid:1;)

.. _http.header:

.. _http.header.raw:

http.header and http.header.raw
-------------------------------

With the ``http.header`` sticky buffer, it is possible to match
specifically and only on the HTTP header buffer. This contains all of
the extracted headers in a single buffer, except for those indicated
in the documentation that are not able to match by this buffer and
have their own sticky buffer (e.g. ``http.cookie``). The sticky buffer
can be used in combination with all previously mentioned content
modifiers, like ``depth``, ``distance``, ``offset``, ``nocase`` and
``within``.

    **Note**: the header buffer is *normalized*. Any trailing
    whitespace and tab characters are removed. See:
    https://lists.openinfosecfoundation.org/pipermail/oisf-users/2011-October/000935.html.
    If there are multiple values for the same header name, they are
    concatenated with a comma and space (", ") between each of them.
    See RFC 2616 4.2 Message Headers.
    To avoid that, use the ``http.header.raw`` keyword.

Example of a header in a HTTP request:



Example of the purpose of ``http.header``:

.. _http.cookie:

http.cookie
-----------

With the ``http.cookie`` sticky buffer it is possible to match
specifically on the HTTP cookie contents. Keywords like ``depth``,
``distance``, ``offset``, ``nocase`` and ``within`` can be used
with ``http.cookie``.

Note that cookies are passed in HTTP headers but Suricata extracts
the cookie data to ``http.cookie`` and will not match cookie content
put in the ``http.header`` sticky buffer.

Example of a cookie in a HTTP request:

Examples::

    GET / HTTP/1.1
    User-Agent: Mozilla/5.0
    Host: www.example.com
    Cookie: PHPSESSIONID=1234
    Connection: close

Example ``http.cookie`` keyword in a signature:

.. container:: example-rule

    alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Request
    with Cookie"; flow:established,to_server; http.method; content:"GET";
    http.uri; content:"/"; fast_pattern; :example-rule-emphasis:`http.cookie;
    content:"PHPSESSIONID="; startswith;` classtype:bad-unknown; sid:123;
    rev:1;)

.. _http.user_agent:

http.user_agent
---------------

The ``http.user_agent`` sticky buffer is part of the HTTP request
header. It makes it possible to match specifically on the value of the
User-Agent header. It is normalized in the sense that it does not
include the _"User-Agent: "_ header name and separator, nor does it
contain the trailing carriage return and line feed (CRLF). The keyword
can be used in combination with all previously mentioned content
modifiers like ``depth``, ``distance``, ``offset``, ``nocase`` and
``within``. Note that the ``pcre`` keyword can also inspect this
buffer when using the ``/V`` modifier.

Normalization: leading spaces **are not** part of this buffer. So
"User-Agent: \r\n" will result in an empty ``http.user_agent`` buffer.

Example of the User-Agent header in a HTTP request:


Example of the purpose of ``http.user_agent``:


Notes
~~~~~

-  The ``http.user_agent`` buffer will NOT include the header name,
   colon, or leading whitespace.  i.e. it will not include
   "User-Agent: ".

-  The ``http.user_agent`` buffer does not include a CRLF (0x0D
   0x0A) at the end.  If you want to match the end of the buffer, use a
   relative ``isdataat`` or a PCRE (although PCRE will be worse on
   performance).

-  If a request contains multiple "User-Agent" headers, the values will
   be concatenated in the ``http.user_agent`` buffer, in the order
   seen from top to bottom, with a comma and space (", ") between each
   of them.

   Example request::

          GET /test.html HTTP/1.1
          User-Agent: SuriTester/0.8
          User-Agent: GGGG

   ``http.user_agent`` buffer contents::

          SuriTester/0.8, GGGG

-  Corresponding PCRE modifier: ``V``

-  Using the ``http.user_agent`` buffer is more efficient when it
   comes to performance than using the ``http.header`` buffer (~10%
   better).

-  `https://blog.inliniac.net/2012/07/09/suricata-http\_user\_agent-vs-http\_header/ <https://blog.inliniac.net/2012/07/09/suricata-http_user_agent-vs-http_header/>`_

.. _http.accept:

http.accept
-----------

Sticky buffer to match on the HTTP Accept header. Only contains the header
value. The \\r\\n after the header are not part of the buffer.

Example::

    alert http any any -> any any (http.accept; content:"image/gif"; sid:1;)

.. _http.accept_enc:

http.accept_enc
---------------

Sticky buffer to match on the HTTP Accept-Encoding header. Only contains the
header value. The \\r\\n after the header are not part of the buffer.

Example::

    alert http any any -> any any (http.accept_enc; content:"gzip"; sid:1;)

.. _http.accept_lang:

http.accept_lang
----------------

Sticky buffer to match on the HTTP Accept-Language header. Only contains the
header value. The \\r\\n after the header are not part of the buffer.

Example::

    alert http any any -> any any (http.accept_lang; content:"en-us"; sid:1;)

.. _http.connection:

http.connection
---------------

Sticky buffer to match on the HTTP Connection header. Only contains the
header value. The \\r\\n after the header are not part of the buffer.

Example::

    alert http any any -> any any (http.connection; content:"keep-alive"; sid:1;)

.. _http.content_type:

http.content_type
-----------------

Sticky buffer to match on the HTTP Content-Type headers. Only contains the
header value. The \\r\\n after the header are not part of the buffer.

Use flow:to_server or flow:to_client to force inspection of request or response.

Examples::

    alert http any any -> any any (flow:to_server; \
            http.content_type; content:"x-www-form-urlencoded"; sid:1;)

    alert http any any -> any any (flow:to_client; \
            http.content_type; content:"text/javascript"; sid:2;)

.. _http.content_len:

http.content_len
----------------

Sticky buffer to match on the HTTP Content-Length headers. Only contains the
header value. The \\r\\n after the header are not part of the buffer.

Use flow:to_server or flow:to_client to force inspection of request or response.

Examples::

    alert http any any -> any any (flow:to_server; \
            http.content_len; content:"666"; sid:1;)

    alert http any any -> any any (flow:to_client; \
            http.content_len; content:"555"; sid:2;)

To do a numeric inspection of the content length, ``byte_test`` can be used.

Example, match if C-L is equal to or bigger than 8079::

    alert http any any -> any any (flow:to_client; \
            http.content_len; byte_test:0,>=,8079,0,string,dec; sid:3;)

.. _http.referer:

http.referer
---------------

Sticky buffer to match on the HTTP Referer header. Only contains the
header value. The \\r\\n after the header are not part of the buffer.

Example::

    alert http any any -> any any (http.referer; content:".php"; sid:1;)

.. _http.start:

http.start
----------

Inspect the start of a HTTP request or response. This will contain the
request/response line plus the request/response headers. Use flow:to_server
or flow:to_client to force inspection of request or response.

Example::

    alert http any any -> any any (http.start; content:"HTTP/1.1|0d 0a|User-Agent"; sid:1;)

The buffer contains the normalized headers and is terminated by an extra
\\r\\n to indicate the end of the headers.

.. _http.header_names:

http.header_names
-----------------

Inspect a buffer only containing the names of the HTTP headers. Useful
for making sure a header is not present or testing for a certain order
of headers.

Buffer starts with a \\r\\n and ends with an extra \\r\\n.

Example buffer::

    \\r\\nHost\\r\\n\\r\\n

Example rule::

    alert http any any -> any any (http.header_names; content:"|0d 0a|Host|0d 0a|"; sid:1;)

Example to make sure *only* Host is present::

    alert http any any -> any any (http.header_names; \
            content:"|0d 0a|Host|0d 0a 0d 0a|"; sid:1;)

Example to make sure *User-Agent* is directly after *Host*::

    alert http any any -> any any (http.header_names; \
            content:"|0d 0a|Host|0d 0a|User-Agent|0d 0a|"; sid:1;)

Example to make sure *User-Agent* is after *Host*, but not necessarily directly after::

    alert http any any -> any any (http.header_names; \
            content:"|0d 0a|Host|0d 0a|"; content:"|0a 0d|User-Agent|0d 0a|"; \
            distance:-2; sid:1;)

.. _http.request_body:

http.request_body
-----------------

With the ``http.request_body`` sticky buffer, it is possible to
match specifically and only on the HTTP request body. The keyword can
be used in combination with all previously mentioned content modifiers
like ``distance``, ``offset``, ``nocase``, ``within``, etc.

Example of ``http.request_body`` in a HTTP request:


Example of the purpose of ``http.client_body``:

Note: how much of the request/client body is inspected is controlled
in the :ref:`libhtp configuration section
<suricata-yaml-configure-libhtp>` via the ``request-body-limit``
setting.

``http.request_body`` replaces the previous keyword name: ```http_client_body``. You may continue
+to use the previous name, but it's recommended that rules be converted to use
+the new name.

.. _http.stat_code:

http.stat_code
--------------

With the ``http.stat_code`` sticky buffer, it is possible to match
specifically and only on the HTTP status code buffer. The keyword can
be used in combination with all previously mentioned content modifiers
like ``distance``, ``offset``, ``nocase``, ``within``, etc.

Example of ``http.stat_code`` in a HTTP response:


Example of the purpose of ``http.stat_code``:

.. _http.stat_msg:

http.stat_msg
-------------

With the ``http.stat_msg`` sticky buffer, it is possible to match
specifically and only on the HTTP status message buffer. The keyword
can be used in combination with all previously mentioned content
modifiers like ``depth``, ``distance``, ``offset``, ``nocase`` and
``within``.

Example of ``http.stat_msg`` in a HTTP response:

Example of the purpose of ``http.stat_msg``:

.. _http.response_line:

http.response_line
------------------

The ``http.response_line`` forces the whole HTTP response line to be inspected.

Example::

    alert http any any -> any any (http.response_line; content:"HTTP/1.0 200 OK"; sid:1;)

.. _http.response_body:

http.response_body
------------------

With the ``http.response_body`` sticky buffer, it is possible to
match specifically and only on the HTTP response body. The keyword can
be used in combination with all previously mentioned content modifiers
like ``distance``, ``offset``, ``nocase``, ``within``, etc.

Note: how much of the response/server body is inspected is controlled
in your :ref:`libhtp configuration section
<suricata-yaml-configure-libhtp>` via the ``response-body-limit``
setting.

Notes
~~~~~

-  Using ``http.response_body`` is similar to having content matches
   that come after ``file.data`` except that it doesn't permanently
   (unless reset) set the detection pointer to the beginning of the
   server response body. i.e. it is not a sticky buffer.

-  ``http.response_body`` will match on gzip decoded data just like
   ``file.data`` does.

-  Since ``http.response_body`` matches on a server response, it
   can't be used with the ``to_server`` or ``from_client`` flow
   directives.

-  Corresponding PCRE modifier: ``Q``

-  further notes at the ``file.data`` section below.

``http.response_body`` replaces the previous keyword name: ```http_server_body``. You may continue
+to use the previous name, but it's recommended that rules be converted to use
+the new name.

.. _http.server:

http.server
-----------

Sticky buffer to match on the HTTP Server headers. Only contains the
header value. The \\r\\n after the header are not part of the buffer.

Example::

    alert http any any -> any any (flow:to_client; \
            http.server; content:"Microsoft-IIS/6.0"; sid:1;)

.. _http.location:

http.location
-------------

Sticky buffer to match on the HTTP Location headers. Only contains the
header value. The \\r\\n after the header are not part of the buffer.

Example::

    alert http any any -> any any (flow:to_client; \
            http.location; content:"http://www.google.com"; sid:1;)

.. _http.host:

.. _http.host.raw:

http.host and http.host.raw
---------------------------

With the ``http.host`` sticky buffer, it is possible to
match specifically and only the normalized hostname.
The ``http.host.raw`` inspects the raw hostname.

The keyword can be used in combination with most of the content modifiers
like ``distance``, ``offset``, ``within``, etc.

The ``nocase`` keyword is not allowed anymore. Keep in mind that you need
to specify a lowercase pattern.

.. _http.request_header:

http.request_header
-------------------

Match on the name and value of a HTTP request header (HTTP1 or HTTP2).

For HTTP2, name and value get concatenated by ": ", colon and space.
To detect if a http2 header name contains ':',
the keyword ``http2.header_name`` can be used.

Examples::

  http.request_header; content:"agent: nghttp2";
  http.request_header; content:"custom-header: I love::colons";

``http.request_header`` is a 'sticky buffer'.

``http.request_header`` can be used as ``fast_pattern``.

.. _http.response_header:

http.response_header
--------------------

Match on the name and value of a HTTP response header (HTTP1 or HTTP2).

For HTTP2, name and value get concatenated by ": ", colon and space.
To detect if a http2 header name contains ':',
the keyword ``http2.header_name`` can be used.

Examples::

  http.response_header; content:"server: nghttp2";
  http.response_header; content:"custom-header: I love::colons";

``http.response_header`` is a 'sticky buffer'.

``http.response_header`` can be used as ``fast_pattern``.

Notes
~~~~~

-  ``http.host`` does not contain the port associated with
   the host (i.e. abc.com:1234). To match on the host and port
   or negate a host and port use ``http.host.raw``.

-  The ``http.host`` and ``http.host.raw`` buffers are populated
   from either the URI (if the full URI is present in the request like
   in a proxy request) or the HTTP Host header. If both are present, the
   URI is used.

-  The ``http.host`` and ``http.host.raw`` buffers will NOT
   include the header name, colon, or leading whitespace if populated
   from the Host header.  i.e. they will not include "Host: ".

-  The ``http.host`` and ``http.host.raw`` buffers do not
   include a CRLF (0x0D 0x0A) at the end.  If you want to match the end
   of the buffer, use a relative 'isdataat' or a PCRE (although PCRE
   will be worse on performance).

-  The ``http.host`` buffer is normalized to be all lower case.

-  The content match that ``http.host`` applies to must be all lower
   case or have the ``nocase`` flag set.

-  ``http.host.raw`` matches the unnormalized buffer so matching
   will be case-sensitive (unless ``nocase`` is set).

-  If a request contains multiple "Host" headers, the values will be
   concatenated in the ``http.host`` and ``http.host.raw``
   buffers, in the order seen from top to bottom, with a comma and space
   (", ") between each of them.

   Example request::

          GET /test.html HTTP/1.1
          Host: ABC.com
          Accept: */*
          Host: efg.net

   ``http.host`` buffer contents::

          abc.com, efg.net

   ``http.host.raw`` buffer contents::

          ABC.com, efg.net

-  Corresponding PCRE modifier (``http_host``): ``W``
-  Corresponding PCRE modifier (``http_raw_host``): ``Z``

.. _file.data:

file.data
---------

With ``file.data``, the HTTP response body is inspected, just like
with ``http.response_body``. The ``file.data`` keyword is a sticky buffer.
``file.data`` also works for HTTP request body and can be used in other
protocols than HTTP1.

Example::

  alert http any any -> any any (file.data; content:"abc"; content:"xyz";)


The ``file.data`` keyword affects all following content matches, until
the ``pkt_data`` keyword is encountered or it reaches the end of the
rule. This makes it a useful shortcut for applying many content
matches to the HTTP response body, eliminating the need to modify each
content match individually.

As the body of a HTTP response can be very large, it is inspected in
smaller chunks.

How much of the response/server body is inspected is controlled
in your :ref:`libhtp configuration section
<suricata-yaml-configure-libhtp>` via the ``response-body-limit``
setting.

If the HTTP body is a flash file compressed with 'deflate' or 'lzma',
it can be decompressed and ``file.data`` can match on the decompress data.
Flash decompression must be enabled under ``libhtp`` configuration:

::

    # Decompress SWF files.
    # 2 types: 'deflate', 'lzma', 'both' will decompress deflate and lzma
    # compress-depth:
    # Specifies the maximum amount of data to decompress,
    # set 0 for unlimited.
    # decompress-depth:
    # Specifies the maximum amount of decompressed data to obtain,
    # set 0 for unlimited.
    swf-decompression:
      enabled: yes
      type: both
      compress-depth: 0
      decompress-depth: 0

Notes
~~~~~

-  file.data is the preferred notation, however, file_data is still
   recognized by the engine and works as well.

-  If a HTTP body is using gzip or deflate, ``file.data`` will match
   on the decompressed data.

-  Negated matching is affected by the chunked inspection. E.g.
   'content:!"<html";' could not match on the first chunk, but would
   then possibly match on the 2nd. To avoid this, use a depth setting.
   The depth setting takes the body size into account.
   Assuming that the ``response-body-minimal-inspect-size`` is bigger
   than 1k, 'content:!"<html"; depth:1024;' can only match if the
   pattern '<html' is absent from the first inspected chunk.

-  Refer to :doc:`file-keywords` for additional information.

Multiple Buffer Matching
~~~~~~~~~~~~~~~~~~~~~~~~

``file.data`` supports multiple buffer matching, see :doc:`multi-buffer-matching`.

.. _file.name:

file.name
---------

The ``file.name`` keyword can be used at the HTTP application level.

Example::

  alert http any any -> any any (msg:"http layer file.name keyword usage"; \
  file.name; content:"picture.jpg"; classtype:bad-unknown; sid:1; rev:1;)

For additional information on the ``file.name`` keyword, see :doc:`file-keywords`.