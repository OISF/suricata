Transformations
===============

Transformation keywords turn the data at a sticky buffer into something else. Some transformations
support options for greater control over the transformation process

Example::

    alert http any any -> any any (file_data; strip_whitespace; \
        content:"window.navigate("; sid:1;)

This example will match on traffic even if there are one or more spaces between
the ``navigate`` and ``(``.

The transforms can be chained. They are processed in the order in which they
appear in a rule. Each transform's output acts as input for the next one.

Example::

    alert http any any -> any any (http_request_line; compress_whitespace; to_sha256; \
        content:"|54A9 7A8A B09C 1B81 3725 2214 51D3 F997 F015 9DD7 049E E5AD CED3 945A FC79 7401|"; sid:1;)

.. note:: not all sticky buffers support transformations yet

dotprefix
---------

Takes the buffer, and prepends a ``.`` character to help facilitate concise domain checks. For example,
an input string of ``hello.google.com`` would be modified and become ``.hello.google.com``. Additionally,
adding the dot allows ``google.com`` to match against ``content:".google.com"``

Example::

    alert dns any any -> any any (dns.query; dotprefix; \
        content:".microsoft.com"; sid:1;)

This example will match on ``windows.update.microsoft.com`` and
``maps.microsoft.com.au`` but not ``windows.update.fakemicrosoft.com``.

This rule can be used to match on the domain only; example::

    alert dns any any -> any any (dns.query; dotprefix; \
        content:".microsoft.com"; endswith; sid:1;)

This example will match on ``windows.update.microsoft.com`` but not
``windows.update.microsoft.com.au``.

Finally, this rule can be used to match on the TLD only; example::

    alert dns any any -> any any (dns.query; dotprefix; \
        content:".co.uk"; endswith; sid:1;)

This example will match on ``maps.google.co.uk`` but not
``maps.google.co.nl``.

strip_whitespace
----------------

Strips all whitespace as considered by the ``isspace()`` call in C.

Example::

    alert http any any -> any any (file_data; strip_whitespace; \
        content:"window.navigate("; sid:1;)

compress_whitespace
-------------------

Compresses all consecutive whitespace into a single space.

to_md5
------

Takes the buffer, calculates the MD5 hash and passes the raw hash value
on.

Example::

    alert http any any -> any any (http_request_line; to_md5; \
        content:"|54 A9 7A 8A B0 9C 1B 81 37 25 22 14 51 D3 F9 97|"; sid:1;)

to_sha1
---------

Takes the buffer, calculates the SHA-1 hash and passes the raw hash value
on.

Example::

    alert http any any -> any any (http_request_line; to_sha1; \
        content:"|54A9 7A8A B09C 1B81 3725 2214 51D3 F997 F015 9DD7|"; sid:1;)

to_sha256
---------

Takes the buffer, calculates the SHA-256 hash and passes the raw hash value
on.

Example::

    alert http any any -> any any (http_request_line; to_sha256; \
        content:"|54A9 7A8A B09C 1B81 3725 2214 51D3 F997 F015 9DD7 049E E5AD CED3 945A FC79 7401|"; sid:1;)

pcrexform
---------

Takes the buffer, applies the required regular expression, and outputs the *first captured expression*.

.. note:: this transform requires a mandatory option string containing a regular expression.


This example alerts if ``http.request_line`` contains ``/dropper.php``
Example::

    alert http any any -> any any (msg:"HTTP with pcrexform"; http.request_line; \
        pcrexform:"[a-zA-Z]+\s+(.*)\s+HTTP"; content:"/dropper.php"; sid:1;)

url_decode
----------

Decodes url-encoded data, ie replacing '+' with space and '%HH' with its value.
This does not decode unicode '%uZZZZ' encoding

xor
---

Takes the buffer, applies xor decoding.

.. note:: this transform requires a mandatory option which is the hexadecimal encoded xor key.


This example alerts if ``http.uri`` contains ``password=`` xored with 4-bytes key ``0d0ac8ff``
Example::

    alert http any any -> any any (msg:"HTTP with xor"; http.uri; \
        xor:"0d0ac8ff"; content:"password="; sid:1;)
