:tocdepth: 2

HTTP Keywords
=============

There are additional content modifiers that can provide
protocol-specific capabilities at the application layer (if you are
unfamiliar with content modifiers, please visit the page [[Payload
keywords]]). These keywords make sure the signature checks only
specific parts of the network traffic. For instance, to check
specifically on the request URI, cookies, or the HTTP request or
response body, etc.


Use ``http_method`` to match on the HTTP request method, ``http_uri``
or ``http_raw_uri`` to match on the request URI, ``http_stat_code`` to
match on the response status code and ``http_stat_msg`` to match on the
response status message.

It is important to understand the structure of HTTP requests and
responses. A simple example of a HTTP request and response follows:

HTTP request
------------

::
   
   GET /index.html HTTP/1.0\r\n

GET is a request **method**.  Examples of methods are: GET, POST, PUT,
HEAD, etc. The URI path is ``/index.html`` and the HTTP version is
``HTTP/1.0``. Several HTTP versions have been used over the years; of
the versions 0.9, 1.0 and 1.1, 1.0 and 1.1 are the most commonly used
today.

HTTP response
-------------

::

   HTTP/1.0 200 OK\r\n
   <html>
   <title> some page </title>
   </HTML>

In this example, HTTP/1.0 is the HTTP version, 200 the response status
code and OK the response status message.

Another more detailed example:

Request:

.. image:: http-keywords/request.png
	   
Response:

.. image:: http-keywords/response1.png

Request:

.. image:: http-keywords/request2.png

Although cookies are sent in an HTTP header, you can not match on them
with the ``http_header`` keyword. Cookies are matched with their own
keyword, namely ``http_cookie``.

Each part of the table belongs to a so-called *buffer*. The HTTP
method belongs to the method buffer, HTTP headers to the header buffer
etc. A buffer is a specific portion of the request or response that
Suricata extracts in memory for inspection.

All previous described keywords can be used in combination with a
buffer in a signature. The keywords ``distance`` and ``within`` are
relative modifiers, so they may only be used within the same
buffer. You can not relate content matches against different buffers
with relative modifiers.

http_method
-----------

With the ``http_method`` content modifier, it is possible to match
specifically and only on the HTTP method buffer. The keyword can be
used in combination with all previously mentioned content modifiers
such as: ``depth``, ``distance``, ``offset``, ``nocase`` and ``within``.

Methods are: **GET**, **POST**, **PUT**, **HEAD**, **DELETE**, **TRACE**,
**OPTIONS**, **CONNECT** and **PATCH**.

Example of a method in a HTTP request:

.. image:: http-keywords/method2.png

Example of the purpose of method:

.. image:: http-keywords/method.png

.. image:: http-keywords/Legenda_rules.png

.. image:: http-keywords/method1.png


http_uri and http_raw_uri
-------------------------

With the ``http_uri`` and the ``http_raw_uri`` content modifiers, it
is possible to match specifically and only on the request URI
buffer. The keyword can be used in combination with all previously
mentioned content modifiers like ``depth``, ``distance``, ``offset``,
``nocase`` and ``within``.

To learn more about the difference between ``http_uri`` and
``http_raw_uri``, please read the information about [[HTTP-uri
normalization]].

Example of the URI in a HTTP request:

.. image:: http-keywords/uri1.png

Example of the purpose of ``http_uri``:

.. image:: http-keywords/uri.png

Example of the purpose of ``http_raw_uri``:

#.. image:: http-keywords/raw_uri.png

uricontent
----------

The ``uricontent`` keyword has the exact same effect as the
``http_uri`` content modifier. ``uricontent`` is a deprecated
(although still supported) way to match specifically and only on the
request URI buffer.

Example of ``uricontent``:

.. image:: http-keywords/uricontent.png

The difference between ``http_uri`` and ``uricontent`` is the syntax:

.. image:: http-keywords/uricontent1.png

.. image:: http-keywords/http_uri.png

When authoring new rules, it is recommended that the ``http_uri``
content modifier be used rather than the deprecated ``uricontent``
keyword.

http_header and http_raw_header
-------------------------------

With the ``http_header`` content modifier, it is possible to match
specifically and only on the HTTP header buffer. This contains all of
the extracted headers in a single buffer, except for those indicated
in the documentation that are not able to match by this buffer and
have their own content modifier (e.g. ``http_cookie``). The modifier
can be used in combination with all previously mentioned content
modifiers, like ``depth``, ``distance``, ``offset``, ``nocase`` and
``within``.

    **Note**: the header buffer is *normalized*. Any trailing
    whitespace and tab characters are removed. See:
    http://lists.openinfosecfoundation.org/pipermail/oisf-users/2011-October/000935.html. Match
    on the ``http_raw_header`` buffer if you require the raw
    (non-normalized) headers.

Example of a header in a HTTP request:

.. image:: http-keywords/header.png

Example of the purpose of ``http_header``:

.. image:: http-keywords/header1.png

http_cookie
-----------

With the ``http_cookie`` content modifier, it is possible to match
specifically and only on the cookie buffer. The keyword can be used in
combination with all previously mentioned content modifiers like
``depth``, ``distance``, ``offset``, ``nocase`` and ``within``.

Note that cookies are passed in HTTP headers, but are extracted to a
dedicated buffer and matched using their own specific content
modifier.

Example of a cookie in a HTTP request:

.. image:: http-keywords/cookie.png

Example of the purpose of ``http_cookie``:

.. image:: http-keywords/cookie1.png

http_user_agent
---------------

The ``http_user_agent`` content modifier is part of the HTTP request
header. It makes it possible to match specifically on the value of the
User-Agent header. It is normalized in the sense that it does not
include the _"User-Agent: "_ header name and separator, nor does it
contain the trailing carriage return and line feed (CRLF). The keyword
can be used in combination with all previously mentioned content
modifiers like ``depth``, ``distance``, ``offset``, ``nocase`` and
``within``. Note that the ``pcre`` keyword can also inspect this
buffer when using the ``/V`` modifier.

An analysis into the performance of ``http_user_agent``
vs. ``http_header`` is found at:
http://blog.inliniac.net/2012/07/09/suricata-http_user_agent-vs-http_header/

Normalization: leading spaces **are not** part of this buffer. So
"User-Agent: \r\n" will result in an empty ``http_user_agent`` buffer.

Example of the User-Agent header in a HTTP request:

.. image:: http-keywords/user_agent.png

Example of the purpose of ``http_user_agent``:

.. image:: http-keywords/user_agent_match.png

http_client_body
----------------

With the ``http_client_body`` content modifier, it is possible to
match specifically and only on the HTTP request body. The keyword can
be used in combination with all previously mentioned content modifiers
like ``distance``, ``offset``, ``nocase``, ``within``, etc.

Example of ``http_client_body`` in a HTTP request:

.. image:: http-keywords/client_body.png

Example of the purpose of ``http_client_body``:

.. image:: http-keywords/client_body1.png

Note: how much of the request/client body is inspected is controlled
in the [[suricata.yaml#Configure-Libhtp]], in the "libhtp" section,
via the ``request-body-limit`` setting.

http_stat_code
--------------

With the ``http_stat_code`` content modifier, it is possible to match
specifically and only on the HTTP status code buffer. The keyword can
be used in combination with all previously mentioned content modifiers
like ``distance``, ``offset``, ``nocase``, ``within``, etc.

Example of ``http_stat_code`` in a HTTP response:

.. image:: http-keywords/stat_code.png

Example of the purpose of ``http_stat_code``:

.. image:: http-keywords/stat-code1.png

http_stat_msg
-------------

With the ``http_stat_msg`` content modifier, it is possible to match
specifically and only on the HTTP status message buffer. The keyword
can be used in combination with all previously mentioned content
modifiers like ``depth``, ``distance``, ``offset``, ``nocase`` and
``within``.

Example of ``http_stat_msg`` in a HTTP response:

.. image:: http-keywords/stat_msg.png

Example of the purpose of ``http_stat_msg``:

.. image:: http-keywords/stat_msg_1.png

http_server_body
----------------

With the ``http_server_body`` content modifier, it is possible to
match specifically and only on the HTTP response body. The keyword can
be used in combination with all previously mentioned content modifiers
like ``distance``, ``offset``, ``nocase``, ``within``, etc. If the
response body is *gzip* encoded, it is first uncompressed for
inspection.

Note: how much of the response/server body is inspected is controlled
in your [[suricata.yaml#Configure-Libhtp]], in the "libhtp" section,
via the ``response-body-limit`` setting.

file_data
---------

With ``file_data``, the HTTP response body is inspected, just like
with ``http_server_body``. The ``file_data`` keyword works a bit
differently from the normal content modifiers; when used in a rule,
all content matches following it in the rule are affected (modified)
by it.

Example::

  alert http any any -> any any (file_data; content:"abc"; content:"xyz";)

.. image:: http-keywords/file_data.png

The ``file_data`` keyword affects all following content matches, until
the ``pkt_data`` keyword is encountered or it reaches the end of the
rule. This makes it a useful shortcut for applying many content
matches to the HTTP response body, eliminating the need to modify each
content match individually. If the response body is *gzip* encoded, it
is first uncompressed for inspection.

Note: how much of the response/server body is inspected is controlled
in your [[suricata.yaml#Configure-Libhtp]], in the "libhtp" section
via the ``response-body-limit`` setting.

**NOTE:** In 2.0.x, ``file_data`` is only supported for HTTP server
bodies (specified as flow direction **to_client**). Starting with
2.1-dev and above, ``file_data`` is handled more intelligently
per-protocol, supported with **to_server** for SMTP and **to_client**
for HTTP.

urilen
------

The ``urilen`` keyword is used to match on the length of the request
URI. It is possible to use the ``<`` and ``>`` operators, which
indicate respectively *smaller than* and *larger than*.

The format of ``urilen`` is::
  
  urilen:3;

Other possibilities are::

  urilen:1;
  urilen:>1;
  urilen:<10;
  urilen:10<>20;	(bigger than 10, smaller than 20)

Example:

.. image:: http-keywords/urilen.png

Example of ``urilen`` in a signature:

.. image:: http-keywords/urilen1.png

You can specify whether the inspected URI buffer is either the
normalized or the raw buffer by appending ``norm`` or ``raw``::

  urilen:<5,raw;

pcre
----

For information about the ``pcre`` keyword, check the [[pcre (Perl
Compatible Regular Expressions)]] page.

fast_pattern
------------

For information about the ``fast_pattern`` keyword, check the
:doc:`fast-pattern` page.
