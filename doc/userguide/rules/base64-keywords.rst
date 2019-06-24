Base64 keywords
===============

Suricata supports decoding base64 encoded data from buffers and matching on the decoded data.

This is achieved by using two keywords, ``base64_decode`` and ``base64_data``. Both keywords must be used in order to generate an alert.

These keywords are compatible with their Snort counterparts.

base64_decode
-------------

Decodes base64_data from a buffer and makes it available for the base64_data function.

Syntax::

    base64_decode:bytes <value>, offset <value>, relative;

The ``bytes`` option specifies how many bytes that should be decoded and made available for base64_data.
The decoding will stop at the end of the buffer.

The ``offset`` option specifies how many bytes to skip before the decoding should start. Bytes are skipped relative to the start of the payload buffer if relative is not set.

The ``relative`` option makes the decoding start relative to the previous content match. Default behavior is to start at the beginning  of the buffer. This option makes ``offset`` skip bytes relative to the previous match.

.. note:: Regarding ``relative`` and ``base64_decode``:

    The content match that you want to decode relative to must be the first match in the stream.

base64_data
-----------

base64_data is a ``sticky buffer``.

Enables content matching on the data previously decoded by base64_decode.

Example
-------

Here is an example of a rule matching on the base64 encoded string "test" that is found inside the http.uri buffer.

It starts decoding relative to the known string "somestring" with the known offset of 1. This must be the first occurrence of "somestring" in the buffer.

.. container:: example-rule

    Buffer content:
    http.uri = "GET /en/somestring&dGVzdAo=&not_base64"

    Rule:
    alert http any any -> any any (content:"somestring"; base64_decode:bytes 8, offset 1, relative; http.uri; base64_content; content:"test"; sid:10001; rev:1;)
