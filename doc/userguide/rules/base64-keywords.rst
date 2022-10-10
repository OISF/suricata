Base64 keywords
===============

Suricata supports decoding base64 encoded data from buffers and matching on the decoded data.

This is achieved by using two keywords, ``base64_decode`` and ``base64_data``. Both keywords must be used in order to generate an alert.

base64_decode
-------------

Decodes base64 data from a buffer and makes it available for the base64_data function.

Syntax::

    base64_decode:bytes <value>, offset <value>, relative;

The ``bytes`` option specifies how many bytes Suricata should decode and make available for base64_data.
The decoding will stop at the end of the buffer.

The ``offset`` option specifies how many bytes Suricata should skip before decoding.
Bytes are skipped relative to the start of the payload buffer if the ``relative`` is not set.

The ``relative`` option makes the decoding start relative to the previous content match. Default behavior is to start at the beginning of the buffer.
This option makes ``offset`` skip bytes relative to the previous match.

.. note:: Regarding ``relative`` and ``base64_decode``:

    The content match that you want to decode relative to must be the first match in the stream.

.. note:: ``base64_decode`` follows RFC 4648 by default i.e. encounter with any character that is not found in the base64 alphabet leads to rejection of that character and the rest of the string.

    See Redmine Bug 5223: https://redmine.openinfosecfoundation.org/issues/5223 and RFC 4648: https://www.rfc-editor.org/rfc/rfc4648#section-3.3

base64_data
-----------

base64_data is a ``sticky buffer``.

Enables content matching on the data previously decoded by base64_decode.

Example
-------

Here is an example of a rule matching on the base64 encoded string "test" that is found inside the http_uri buffer.

It starts decoding relative to the known string "somestring" with the known offset of 1. This must be the first occurrence of "somestring" in the buffer.

Example::

    Buffer content:
    http_uri = "GET /en/somestring&dGVzdAo=&not_base64"

    Rule:
    alert http any any -> any any (msg:"Example"; http.uri; content:"somestring"; \
         base64_decode:bytes 8, offset 1, relative; \
         base64_data; content:"test"; sid:10001; rev:1;)

    Buffer content:
    http_uri = "GET /en/somestring&dGVzdAo=&not_base64"

    Rule:
    alert http any any -> any any (msg:"Example"; content:"somestring"; http_uri; \
         base64_decode:bytes 8, offset 1, relative; \
         base64_data; content:"test"; sid:10001; rev:1;)
