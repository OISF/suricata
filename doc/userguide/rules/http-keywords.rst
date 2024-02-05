HTTP Keywords
=============

.. role:: example-rule-action
.. role:: example-rule-header
.. role:: example-rule-options
.. role:: example-rule-emphasis

Using the HTTP specific sticky buffers (see :ref:`rules-modifiers`) provides a
way to efficiently inspect the specific fields of HTTP protocol communications.
After specifying a sticky buffer in a rule it should be followed by one or
more :doc:`payload-keywords` or using :ref:`pcre`.

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
 * :ref:`urilen`

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
 * :ref:`http.header.raw`
 * :ref:`http.cookie`

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

It is possible to use any of the :doc:`payload-keywords` with both ``http.uri``
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

The ``urilen`` keyword is used to match on the length of the normalized request
URI. It is possible to use the ``<`` and ``>`` operators, which
indicate respectively *less than* and *larger than*.

urilen uses an :ref:`unsigned 64-bit integer <rules-integer-keywords>`.

The ``urilen`` keyword does not require a content match on the :ref:`http.uri`
buffer or the :ref:`http.uri.raw` buffer.

Example HTTP Request::

  GET /index.html HTTP/1.1
  User-Agent: Mozilla/5.0
  Host: suricata.io

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Request"; \
  flow:established,to_server; :example-rule-options:`urilen:11;` \
  http.method; content:"GET"; classtype:bad-unknown; sid:40; rev:1;)

The above signature would match on any HTTP GET request that has a URI
length of 11, regardless of the content or structure of the URI.

The following signatures would all alert on the example request above as well
and show the different ``urilen`` options.

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"urilen greater than 10"; \
  flow:established,to_server; :example-rule-options:`urilen:>10;` \
  classtype:bad-unknown; sid:41; rev:1;)

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"urilen less than 12"; \
  flow:established,to_server; :example-rule-options:`urilen:<12;` \
  classtype:bad-unknown; sid:42; rev:1;)

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"urilen greater/less than \
  example"; flow:established,to_server; :example-rule-options:`urilen:10<>12;` \
  classtype:bad-unknown; sid:43; rev:1;)

.. _http.protocol:

http.protocol
-------------

The ``http.protocol`` keyword is used to match on the protocol field that is
contained in HTTP requests and responses.

It is possible to use any of the :doc:`payload-keywords` with the
``http.protocol`` keyword.

.. note:: ``http.protocol`` does not include the leading space or trailing \\r\\n

Example HTTP Request::

  GET /index.html HTTP/1.1
  User-Agent: Mozilla/5.0
  Host: suricata.io

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Protocol Example"; \
  flow:established,to_server; :example-rule-options:`http.protocol; \
  content:"HTTP/1.1";` bsize:9; classtype:bad-unknown; sid:50; rev:1;)

.. _http.request_line:

http.request_line
-----------------

The ``http.request_line`` keyword is used to match on the entire contents of
the HTTP request line.

Example HTTP Request::

  GET /index.html HTTP/1.1
  User-Agent: Mozilla/5.0
  Host: suricata.io

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Request Example"; \
  flow:established,to_server; :example-rule-options:`http.request_line; \
  content:"GET /index.html HTTP/1.1";` bsize:24; classtype:bad-unknown; \
  sid:60; rev:1;)

.. note:: ``http.request_line`` does not include the trailing \\r\\n

.. _http.header:

http.header
-----------

Matching on HTTP headers has two options in Suricata, the ``http.header``
and the ``http.header.raw``.

It is possible to use any of the :doc:`payload-keywords` with both
``http.header`` keywords.

The ``http.header`` keyword normalizes the header contents. For example if
header contents contain trailing white-space or tab characters, those would be
removed.

To match on non-normalized header data, use the :ref:`http.header.raw` keyword.

Normalization Example::

  GET /index.html HTTP/1.1
  User-Agent: Mozilla/5.0     \r\n
  Host: suricata.io

Would be normalized to :example-rule-emphasis:`Mozilla/5.0\\r\\n`

Example HTTP Request::

  GET /index.html HTTP/1.1
  User-Agent: Mozilla/5.0
  Host: suricata.io

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Header Example 1"; \
  flow:established,to_server; :example-rule-options:`http.header; \
  content:"User-Agent|3a 20|Mozilla/5.0|0d 0a|";` classtype:bad-unknown; \
  sid:70; rev:1;)

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Header Example 2"; \
  flow:established,to_server; :example-rule-options:`http.header; \
  content:"Host|3a 20|suricata.io|0d 0a|";` classtype:bad-unknown; \
  sid:71; rev:1;)

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Header Example 3"; \
  flow:established,to_server; :example-rule-options:`http.header; \
  content:"User-Agent|3a 20|Mozilla/5.0|0d 0a|"; startswith; \
  content:"Host|3a 20|suricata.io|0d 0a|";` classtype:bad-unknown; \
  sid:72; rev:1;)

.. note:: There are headers that will not be included in the ``http.header``
  buffer, specifically the :ref:`http.cookie` buffer.

.. note:: If there are multiple values for the same header name, they are
  concatenated with a comma and space (", ") between each value.
  More information can be found in RFC 2616
  `<https://www.rfc-editor.org/rfc/rfc2616.html#section-4.2>`_

.. _http.header.raw:

http.header.raw
---------------

The ``http.header.raw`` buffer matches on HTTP header content but does not have
any normalization performed on the buffer contents (see :ref:`http.header`)

Abnormal HTTP Header Example::

  GET /index.html HTTP/1.1
  User-Agent: Mozilla/5.0
  User-Agent: Chrome
  Host: suricata.io

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Header Raw Example"; \
  flow:established,to_server; :example-rule-options:`http.header.raw; \
  content:"User-Agent|3a 20|Mozilla/5.0|0d 0a|"; \
  content:"User-Agent|3a 20|Chrome|0d 0a|";` classtype:bad-unknown; sid:73; rev:1;)

.. _http.cookie:

http.cookie
-----------

The ``http.cookie`` keyword is used to match on the cookie field that can be
present in HTTP request (Cookie) or HTTP response (Set-Cookie) headers.

It is possible to use any of the :doc:`payload-keywords` with both ``http.header``
keywords.

.. note:: Cookies are passed in HTTP headers but Suricata extracts the cookie
  data to ``http.cookie`` and will not match cookie content put in the
  :ref:`http.header` sticky buffer.

.. note:: ``http.cookie`` does not include the leading space or trailing \\r\\n

Example HTTP Request::

  GET /index.html HTTP/1.1
  User-Agent: Mozilla/5.0
  Cookie: PHPSESSION=123
  Host: suricata.io

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Cookie Example"; \
  flow:established,to_server; :example-rule-emphasis:`http.cookie; \
  content:"PHPSESSIONID=123";` bsize:14; classtype:bad-unknown; sid:80; rev:1;)

.. _http.user_agent:

http.user_agent
---------------

The ``http.user_agent`` keyword is used to match on the User-Agent field that
can be present in HTTP request headers.

It is possible to use any of the :doc:`payload-keywords` with the
``http.user_agent`` keyword.

Example HTTP Request::

  GET /index.html HTTP/1.1
  User-Agent: Mozilla/5.0
  Cookie: PHPSESSION=123
  Host: suricata.io

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP User-Agent Example"; \
  flow:established,to_server; :example-rule-options:`http.user_agent; \
  content:"Mozilla/5.0";` bsize:11; classtype:bad-unknown; sid:90; rev:1;)

.. note:: ``http.user_agent`` does not include the leading space or trailing
   \\r\\n

.. note:: Using the ``http.user_agent`` generally provides better performance
   than using :ref:`http.header`.

.. note:: If a request contains multiple "User-Agent" headers, the values will
   be concatenated in the ``http.user_agent`` buffer, in the order seen from
   top to bottom, with a comma and space (", ") between each of them.

Example Duplicate User-Agent Header Request::

  GET /index.html HTTP/1.1
  User-Agent: Mozilla/5.0
  User-Agent: Chrome/2.0
  Cookie: PHPSESSION=123
  Host: suricata.io

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP User-Agent Example"; \
  flow:established,to_server; :example-rule-options:`http.user_agent; \
  content:"Mozilla/5.0, Chrome/2.0";` bsize:23; classtype:bad-unknown; sid:90; \
  rev:1;)

.. _http.accept:

http.accept
-----------

The ``http.accept`` keyword is used to match on the Accept field that
can be present in HTTP request headers.

It is possible to use any of the :doc:`payload-keywords` with the
``http.accept`` keyword.

Example HTTP Request::

  GET /index.html HTTP/1.1
  User-Agent: Mozilla/5.0
  Accept: */*
  Host: suricata.io

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Accept Example"; \
  flow:established,to_server; :example-rule-options:`http.accept; \
  content:"*/*";` bsize:3; classtype:bad-unknown; sid:91; rev:1;)

.. note:: ``http.accept`` does not include the leading space or trailing \\r\\n

.. _http.accept_enc:

http.accept_enc
---------------

The ``http.accept_enc`` keyword is used to match on the Accept-Encoding field
that can be present in HTTP request headers.

It is possible to use any of the :doc:`payload-keywords` with the
``http.accept_enc`` keyword.

Example HTTP Request::

  GET /index.html HTTP/1.1
  User-Agent: Mozilla/5.0
  Accept-Encoding: gzip, deflate
  Host: suricata.io

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Accept-Encoding Example"; \
  flow:established,to_server; :example-rule-options:`http.accept_enc; \
  content:"gzip, deflate";` bsize:13; classtype:bad-unknown; sid:92; rev:1;)

.. note:: ``http.accept_enc`` does not include the leading space or trailing
   \\r\\n

.. _http.accept_lang:

http.accept_lang
----------------

The ``http.accept_lang`` keyword is used to match on the Accept-Language field
that can be present in HTTP request headers.

It is possible to use any of the :doc:`payload-keywords` with the
``http.accept_lang`` keyword.

Example HTTP Request::

  GET /index.html HTTP/1.1
  User-Agent: Mozilla/5.0
  Accept-Language: en-US
  Host: suricata.io

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Accept-Encoding Example"; \
  flow:established,to_server; :example-rule-options:`http.accept_lang; \
  content:"en-US";` bsize:5; classtype:bad-unknown; sid:93; rev:1;)

.. note:: ``http.accept_lang`` does not include the leading space or
  trailing \\r\\n

.. _http.connection:

http.connection
---------------

The ``http.connection`` keyword is used to match on the Connection field that
can be present in HTTP request headers.

It is possible to use any of the :doc:`payload-keywords` with the
``http.connection`` keyword.

Example HTTP Request::

  GET /index.html HTTP/1.1
  User-Agent: Mozilla/5.0
  Accept-Language: en-US
  Host: suricata.io
  Connection: Keep-Alive

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Connection Example"; \
  flow:established,to_server; :example-rule-options:`http.connection; \
  content:"Keep-Alive";` bsize:10; classtype:bad-unknown; sid:94; rev:1;)

.. note:: ``http.connection`` does not include the leading space or trailing
   \\r\\n

.. _http.content_type:

http.content_type
-----------------

The ``http.content_type`` keyword is used to match on the Content-Type field that
can be present in HTTP request or response headers. Use ``flow:to_server`` or
``flow:to_client`` to force inspection of the request or response respectively.

It is possible to use any of the :doc:`payload-keywords` with the
``http.content_type`` keyword.

Example HTTP Request::

  POST /suricata.php HTTP/1.1
  Content-Type: multipart/form-data; boundary=---------------123
  Host: suricata.io
  Content-Length: 100
  Connection: Keep-Alive

Example HTTP Response::

  HTTP/1.1 200 OK
  Content-Type: text/html
  Server: nginx/0.8.54
  Connection: Close

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Content-Type Request \
  Example"; flow:established,to_server; :example-rule-options:`http.content_type; \
  content:"multipart/form-data|3b 20|";` startswith; classtype:bad-unknown; \
  sid:95; rev:1;)

  alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP Content-Type Response \
  Example"; flow:established,to_client; :example-rule-options:`http.content_type; \
  content:"text/html";` bsize:9; classtype:bad-unknown; sid:96; rev:1;)

.. note:: ``http.content_type`` does not include the leading space or trailing
   \\r\\n

.. _http.content_len:

http.content_len
----------------

The ``http.content_len`` keyword is used to match on the Content-Length field that
can be present in HTTP request or response headers. Use ``flow:to_server`` or
``flow:to_client`` to force inspection of the request or response respectively.

It is possible to use any of the :doc:`payload-keywords` with the
``http.content_len`` keyword.

Example HTTP Request::

  POST /suricata.php HTTP/1.1
  Content-Type: multipart/form-data; boundary=---------------123
  Host: suricata.io
  Content-Length: 100
  Connection: Keep-Alive

Example HTTP Response::

  HTTP/1.1 200 OK
  Content-Type: text/html
  Server: nginx/0.8.54
  Connection: Close
  Content-Length: 20

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Content-Length Request \
  Example"; flow:established,to_server; :example-rule-options:`http.content_len; \
  content:"100";` bsize:3; classtype:bad-unknown; sid:97; rev:1;)

  alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP Content-Length Response \
  Example"; flow:established,to_client; :example-rule-options:`http.content_len; \
  content:"20";` bsize:2; classtype:bad-unknown; sid:98; rev:1;)

To do numeric evaluation of the content length, :ref:`byte_test` can be used.

If we want to match on an HTTP request content length equal to and greater
than 100 we could use the following signature.

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Content-Length Request \
  Byte Test Example"; flow:established,to_server; \
  :example-rule-options:`http.content_len; byte_test:0,>=,100,0,string,dec;` \
  classtype:bad-unknown; sid:99; rev:1;)

.. note:: ``http.content_len`` does not include the leading space or trailing
   \\r\\n

.. _http.referer:

http.referer
------------

The ``http.referer`` keyword is used to match on the Referer field that
can be present in HTTP request headers.

It is possible to use any of the :doc:`payload-keywords` with the
``http.referer`` keyword.

Example HTTP Request::

  GET / HTTP/1.1
  Host: suricata.io
  Referer: https://suricata.io

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Referer Example"; \
  flow:established,to_server; :example-rule-options:`http.referer; \
  content:"http|3a 2f 2f|suricata.io";` bsize:19; classtype:bad-unknown; \
  sid:200; rev:1;)

.. note:: ``http.referer`` does not include the leading space or trailing
   \\r\\n

.. _http.start:

http.start
----------

The ``http.start`` keyword is used to match on the start of an HTTP request
or response. This will contain the request/response line plus the request/response
headers. Use ``flow:to_server`` or ``flow:to_client`` to force inspection of the
request or response respectively.

It is possible to use any of the :doc:`payload-keywords` with the
``http.start`` keyword.

Example HTTP Request::

  GET / HTTP/1.1
  Host: suricata.io
  Connection: Keep-Alive

Example HTTP Response::

  HTTP/1.1 200 OK
  Content-Type: text/html
  Server: nginx/0.8.54

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Start Request \
  Example"; flow:established,to_server; :example-rule-options:`http.start; \
  content:"POST / HTTP/1.1|0d 0a|Host|0d 0a|Connection|0d 0a 0d 0a|";` \
  classtype:bad-unknown; sid:101; rev:1;)

  alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP Start Response \
  Example"; flow:established,to_client; :example-rule-options:`http.start; \
  content:"HTTP/1.1 200 OK|0d 0a|Content-Type|0d 0a|Server|0d 0a 0d a0|";` \
  classtype:bad-unknown; sid:102; rev:1;)

.. note:: ``http.start`` contains the normalized headers and is terminated by
  an extra \\r\\n to indicate the end of the headers.

.. _http.header_names:

http.header_names
-----------------

The ``http.header_names`` keyword is used to match on the names of the headers
in an HTTP request or response. This is useful for checking for a headers
presence, absence and/or header order. Use ``flow:to_server`` or
``flow:to_client`` to force inspection of the request or response respectively.

It is possible to use any of the :doc:`payload-keywords` with the
``http.header_names`` keyword.

Example HTTP Request::

  GET / HTTP/1.1
  Host: suricata.io
  Connection: Keep-Alive

Example HTTP Response::

  HTTP/1.1 200 OK
  Content-Type: text/html
  Server: nginx/0.8.54

Examples to match exactly on header order:

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Header Names Request \
  Example"; flow:established,to_server; :example-rule-options:`http.header_names; \
  content:"|0d 0a|Host|0d 0a|Connection|0d 0a 0d 0a|";` bsize:22; \
  classtype:bad-unknown; sid:110; rev:1;)

  alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP Header Names Response \
  Example"; flow:established,to_client; :example-rule-options:`http.header_names; \
  content:"|0d 0a|Content-Type|0d 0a|Server|0d 0a 0d a0|";` bsize:26; \
  classtype:bad-unknown; sid:111; rev:1;)

Examples to match on header existence:

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Header Names Request \
  Example 2"; flow:established,to_server; :example-rule-options:`http.header_names; \
  content:"|0d 0a|Host|0d 0a|";` classtype:bad-unknown; sid:112; rev:1;)

  alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP Header Names Response \
  Example 2"; flow:established,to_client; :example-rule-options:`http.header_names; \
  content:"|0d 0a|Content-Type|0d 0a|";` classtype:bad-unknown; sid:113; rev:1;)

Examples to match on header absence:

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Header Names Request \
  Example 3"; flow:established,to_server; :example-rule-options:`http.header_names; \
  content:!"|0d 0a|User-Agent|0d 0a|";` classtype:bad-unknown; sid:114; rev:1;)

  alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP Header Names Response \
  Example 3"; flow:established,to_client; :example-rule-options:`http.header_names; \
  content:!"|0d 0a|Date|0d 0a|";` classtype:bad-unknown; sid:115; rev:1;)

Example to check for the ``User-Agent`` header and that the ``Host`` header is
after ``User-Agent`` but not necessarily directly after.

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Header Names Request \
  Example 4"; flow:established,to_server; :example-rule-options:`http.header_names; \
  content:"|0d 0a|Host|0d 0a|";` content:"User-Agent|0d 0a|"; distance:-2; \
  classtype:bad-unknown; sid:114; rev:1;)

.. note:: ``http.header_names`` starts with a \\r\\n and ends with an extra \\r\\n.

.. _http.request_body:

http.request_body
-----------------

The ``http.request_body`` keyword is used to match on the HTTP request body
that can be present in an HTTP request.

It is possible to use any of the :doc:`payload-keywords` with the
``http.request_body`` keyword.

Example HTTP Request::

  POST /suricata.php HTTP/1.1
  Content-Type: application/x-www-form-urlencoded
  Host: suricata.io
  Content-Length: 23
  Connection: Keep-Alive

  Suricata request body

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Request Body Example"; \
  flow:established,to_server; :example-rule-options:`http.request_body; \
  content:"Suricata request body";` classtype:bad-unknown; sid:115; rev:1;)

.. note:: How much of the request/client body is inspected is controlled
  in the :ref:`libhtp configuration section
  <suricata-yaml-configure-libhtp>` via the ``request-body-limit``
  setting.

.. note:: ``http.request_body`` replaces the previous keyword name,
  ``http_client_body``. ``http_client_body`` can still be used but it is
  recommended that rules be converted to use ``http.request_body``.

.. _http.stat_code:

http.stat_code
--------------

The ``http.stat_code`` keyword is used to match on the HTTP status code
that can be present in an HTTP response.

It is possible to use any of the :doc:`payload-keywords` with the
``http.stat_code`` keyword.

Example HTTP Response::

  HTTP/1.1 200 OK
  Content-Type: text/html
  Server: nginx/0.8.54

.. container:: example-rule

  alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP Stat Code Response \
  Example"; flow:established,to_client; :example-rule-options:`http.stat_code; \
  content:"200";` classtype:bad-unknown; sid:117; rev:1;)

.. note:: ``http.stat_code`` does not include the leading or trailing space

.. _http.stat_msg:

http.stat_msg
-------------

The ``http.stat_msg`` keyword is used to match on the HTTP status message
that can be present in an HTTP response.

It is possible to use any of the :doc:`payload-keywords` with the
``http.stat_msg`` keyword.

Example HTTP Response::

  HTTP/1.1 200 OK
  Content-Type: text/html
  Server: nginx/0.8.54

.. container:: example-rule

  alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP Stat Message Response \
  Example"; flow:established,to_client; :example-rule-options:`http.stat_msg; \
  content:"OK";` classtype:bad-unknown; sid:118; rev:1;)

.. note:: ``http.stat_msg`` does not include the leading space or trailing \\r\\n

.. note:: ``http.stat_msg`` will always be empty when used with HTTP/2

.. _http.response_line:

http.response_line
------------------

The ``http.response_line`` keyword is used to match on the entire HTTP
response line.

It is possible to use any of the :doc:`payload-keywords` with the
``http.response_line`` keyword.

Example HTTP Response::

  HTTP/1.1 200 OK
  Content-Type: text/html
  Server: nginx/0.8.54

.. container:: example-rule

  alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP Response Line \
  Example"; flow:established,to_client; :example-rule-options:`http.response_line; \
  content:"HTTP/1.1 200 OK";` classtype:bad-unknown; sid:119; rev:1;)

.. note:: ``http.response_line`` does not include the trailing \\r\\n

.. _http.response_body:

http.response_body
------------------

The ``http.response_body`` keyword is used to match on the HTTP response body.

It is possible to use any of the :doc:`payload-keywords` with the
``http.response_body`` keyword.

Example HTTP Response::

  HTTP/1.1 200 OK
  Content-Type: text/html
  Server: nginx/0.8.54

  Server response body

.. container:: example-rule

  alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP Response Body \
  Example"; flow:established,to_client; :example-rule-options:`http.response_body; \
  content:"Server response body";` classtype:bad-unknown; sid:120; rev:1;)

.. note:: ``http.response_body`` will match on gzip decoded data just like
  :ref:`file.data` does.

.. note:: How much of the response/server body is inspected is controlled
  in your :ref:`libhtp configuration section
  <suricata-yaml-configure-libhtp>` via the ``response-body-limit``
  setting.

.. note:: ``http.response_body`` replaces the previous keyword name,
  ``http_server_body``. ``http_server_body`` can still be used but it is
  recommended that rules be converted to use ``http.response_body``.

.. _http.server:

http.server
-----------

The ``http.server`` keyword is used to match on the HTTP response server
header contents.

It is possible to use any of the :doc:`payload-keywords` with the
``http.server`` keyword.

Example HTTP Response::

  HTTP/1.1 200 OK
  Content-Type: text/html
  Server: nginx/0.8.54

.. container:: example-rule

  alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP Server Example"; flow:established,to_client; :example-rule-options:`http.server; \
  content:"nginx/0.8.54";` bsize:12; classtype:bad-unknown; sid:121; rev:1;)

.. note:: ``http.server`` does not include the leading space or trailing \\r\\n

.. _http.location:

http.location
-------------

The ``http.location`` keyword is used to match on the HTTP response location
header contents.

It is possible to use any of the :doc:`payload-keywords` with the
``http.location`` keyword.

Example HTTP Response::

  HTTP/1.1 200 OK
  Content-Type: text/html
  Server: nginx/0.8.54
  Location: suricata.io

.. container:: example-rule

  alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"HTTP Location Example"; \
  flow:established,to_client; :example-rule-options:`http.location; \
  content:"suricata.io";` bsize:11; classtype:bad-unknown; sid:122; rev:1;)

.. note:: ``http.location`` does not include the leading space or trailing \\r\\n

.. _http.host:

http.host
---------

Matching on the HTTP host name has two options in Suricata, the ``http.host``
and the ``http.host.raw`` sticky buffers.

It is possible to use any of the :doc:`payload-keywords` with both ``http.host``
keywords.

.. note:: The ``http.host`` keyword normalizes the host header contents. If a
  host name has uppercase characters, those would be changed to lowercase.

Normalization Example::

  GET /index.html HTTP/1.1
  User-Agent: Mozilla/5.0
  Host: SuRiCaTa.Io

In the above example the host buffer would contain `suricata.io`.

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Host Example"; \
  flow:established,to_server; :example-rule-options:`http.host; \
  content:"suricata.io";` bsize:11; classtype:bad-unknown; sid:123; rev:1;)

.. note:: The ``nocase`` keyword is no longer allowed since the host names
  are normalized to contain only lowercase letters.

.. note:: ``http.host`` does not contain the port associated with the host
  (i.e. suricata.io:1234). To match on the host and port or negate a host
  and port use :ref:`http.host.raw`.

.. note:: ``http.host`` does not include the leading space or trailing \\r\\n

.. note:: The ``http.host`` and ``http.host.raw`` buffers are populated
  from either the URI (if the full URI is present in the request like
  in a proxy request) or the HTTP Host header. If both are present, the
  URI is used.

.. note:: If a request contains multiple "Host" headers, the values will be
  concatenated in the ``http.host`` and ``http.host.raw``
  buffers, in the order seen from top to bottom, with a comma and space
  (", ") between each of them.

Example Duplicate Host Header Request::

  GET /index.html HTTP/1.1
  User-Agent: Chrome/2.0
  Cookie: PHPSESSION=123
  Host: suricata.io
  Host: oisf.net

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Two Host Example"; \
  flow:established,to_server; :example-rule-options:`http.host; \
  content:"suricata.io, oisf.net";` classtype:bad-unknown; sid:125; rev:1;)

.. _http.host.raw:

http.host.raw
-------------

The ``http.host.raw`` buffer matches on HTTP host content but does not have
any normalization performed on the buffer contents (see :ref:`http.host`)

Example HTTP Request::

  GET /index.html HTTP/1.1
  User-Agent: Mozilla/5.0
  Host: SuRiCaTa.Io:8445

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Host Raw Example"; \
  flow:established,to_server; :example-rule-options:`http.host.raw; \
  content:"SuRiCaTa.Io|3a|8445";` bsize:16; classtype:bad-unknown; sid:124; rev:1;)

.. note:: ``http.host.raw`` does not include the leading space or trailing \\r\\n

.. note:: The ``http.host`` and ``http.host.raw`` buffers are populated
  from either the URI (if the full URI is present in the request like
  in a proxy request) or the HTTP Host header. If both are present, the
  URI is used.

.. note:: If a request contains multiple "Host" headers, the values will be
  concatenated in the ``http.host`` and ``http.host.raw`` buffers, in the
  order seen from top to bottom, with a comma and space (", ") between each
  of them.

Example Duplicate Host Header Request::

  GET /index.html HTTP/1.1
  User-Agent: Chrome/2.0
  Cookie: PHPSESSION=123
  Host: suricata.io
  Host: oisf.net

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Two Host Example"; \
  flow:established,to_server; :example-rule-options:`http.host.raw; \
  content:"suricata.io, oisf.net";` classtype:bad-unknown; sid:125; rev:1;)

.. _http.request_header:

http.request_header
-------------------

The ``http.request_header`` keyword is used to match on the name and value
of a HTTP/1 or HTTP/2 request.

It is possible to use any of the :doc:`payload-keywords` with the
``http.request_header`` keyword.

For HTTP/2, the header name and value get concatenated by ": " (colon and space).
The colon and space are commonly noted with the hexadecimal format `|3a 20|`
within signatures.

To detect if an HTTP/2 header name contains a ":" (colon), the keyword
:ref:`http2.header_name` can be used.

Example HTTP/1 Request::

  GET /index.html HTTP/1.1
  User-Agent: Mozilla/5.0
  Host: suricata.io

.. container:: example-rule

  alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP Request Example"; \
  flow:established,to_server; :example-rule-options:`http.request_header; \
  content:"Host|3a 20|suricata.io";` classtype:bad-unknown; sid:126; rev:1;)

.. note:: ``http.request_header`` does not include the trailing \\r\\n

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