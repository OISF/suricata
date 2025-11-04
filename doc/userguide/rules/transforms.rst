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

domain
------

Takes the buffer and extracts the domain name from it. The domain name is defined
using `Mozilla’s Public Suffix List <https://publicsuffix.org/>`_. This implies
that it is using traditional top level domain such as ``.com`` but also some
specific domain like ``airport.aero`` or ``execute-api.cn-north-1.amazonaws.com.cn``
where declaration of sub domain by users below the domain is possible.

Example::

    alert tls any any -> any any (tls.sni; domain; \
        dataset:isset,domains,type string,load domains.lst; sid:1;)

This example will match on all domains contained in the file ``domains.lst``.
For example, if ``domains.lst`` contains ``oisf.net`` then  ``webshop.oisf.net`` will match.


tld
---

Takes the buffer and extracts the Top Level Domain (TLD) name from it. The TLD name is defined
using `Mozilla’s Public Suffix List <https://publicsuffix.org/>`_. This implies
that it is will have traditional TLD such as ``com`` but also some
specific domain like ``airport.aero`` or ``execute-api.cn-north-1.amazonaws.com.cn``
where declaration of sub domain by users below the domain is possible.

Example::

    alert tls any any -> any any (tls.sni; tld; \
        dataset:isset,tlds,type string,load tlds.lst; sid:1;)

This example will match on all TLDs contained in the file ``tlds.lst``. For example, if
``tlds.lst`` contains ``net`` then  ``oisf.net`` will match.


strip_whitespace
----------------

Strips all whitespace as considered by the ``isspace()`` call in C.

Example::

    alert http any any -> any any (file_data; strip_whitespace; \
        content:"window.navigate("; sid:1;)

compress_whitespace
-------------------

Compresses all consecutive whitespace into a single space.

to_lowercase
------------

Converts the buffer to lowercase and passes the value on.

This example alerts if ``http.uri`` contains ``this text has been converted to lowercase``

Example::

    alert http any any -> any any (http.uri; to_lowercase; \
        content:"this text has been converted to lowercase"; sid:1;)

to_md5
------

Takes the buffer, calculates the MD5 hash and passes the raw hash value
on.

Example::

    alert http any any -> any any (http_request_line; to_md5; \
        content:"|54 A9 7A 8A B0 9C 1B 81 37 25 22 14 51 D3 F9 97|"; sid:1;)

to_uppercase
------------

Converts the buffer to uppercase and passes the value on.

This example alerts if ``http.uri`` contains ``THIS TEXT HAS BEEN CONVERTED TO UPPERCASE``

Example::

    alert http any any -> any any (http.uri; to_uppercase; \
        content:"THIS TEXT HAS BEEN CONVERTED TO UPPERCASE"; sid:1;)

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

header_lowercase
----------------

This transform is meant for HTTP/1 HTTP/2 header names normalization.
It lowercases the header names, while keeping untouched the header values.

The implementation uses a state machine :
- it lowercases until it finds ``:```
- it does not change until it finds a new line and switch back to first state

This example alerts for both HTTP/1 and HTTP/2 with a authorization header
Example::

    alert http any any -> any any (msg:"HTTP authorization"; http.header_names; \
        header_lowercase; content:"authorization:"; sid:1;)

strip_pseudo_headers
--------------------

This transform is meant for HTTP/1 HTTP/2 header names normalization.
It strips HTTP2 pseudo-headers (names and values).

The implementation just strips every line beginning by ``:``.

This example alerts for both HTTP/1 and HTTP/2 with only a user agent
Example::

    alert http any any -> any any (msg:"HTTP ua only"; http.header_names; \
       bsize:16; content:"|0d 0a|User-Agent|0d 0a 0d 0a|"; nocase; sid:1;)

.. _from_base64:

from_base64
-----------

This transform is similar to the keyword ``base64_decode``: the buffer is decoded using
the optional values for ``mode``, ``offset`` and ``bytes`` and is available for matching
on the decoded data.

After this transform completes, the buffer will contain only bytes that could be bases64-decoded.
If the decoding process encountered invalid bytes, those will not be included in the buffer.

The option values must be ``,`` separated and can appear in any order.

.. note:: ``from_base64`` follows RFC 4648 by default i.e. encounter with any character
   that is not found in the base64 alphabet leads to rejection of that character and the
   rest of the string.

Format::

    from_base64: [[bytes <value>] [, offset <offset_value> [, mode: strict|rfc4648|rfc2045]]]
    from_base64

There are defaults for each of the options:
- ``bytes`` defaults to the length of the input buffer
- ``offset`` defaults to ``0`` and must be less than ``65536``
- ``mode`` defaults to ``rfc4648``

The second example shows the rule keyword only which will cause the default values for each option to
be used.

Note that both ``bytes`` and ``offset`` may be variables from `byte_extract` and/or `byte_math` in
later versions of Suricata. They are not supported yet.

Mode ``rfc4648`` applies RFC 4648 decoding logic which is suitable for encoding binary
data that can be safely sent by email, used in a URL, or included with HTTP POST requests.

Mode ``rfc2045`` applies RFC 2045 decoding logic which supports strings, including those with embedded spaces,
line breaks, and any non base64 alphabet.

Mode ``strict`` will fail if an invalid character is found in the encoded bytes.

The following examples will alert when the buffer contents match (see the
last ``content`` value for the expected strings).

This example uses the defaults and transforms `"VGhpcyBpcyBTdXJpY2F0YQ=="` to `"This is Suricata"`::

       content: "VGhpcyBpcyBTdXJpY2F0YQ=="; from_base64; content:"This is Suricata";

This example transforms `"dGhpc2lzYXRlc3QK"` to `"thisisatest"`::

       content:"/?arg=dGhpc2lzYXRlc3QK"; from_base64: offset 6, mode rfc4648; \
       content:"thisisatest";

This example transforms `"Zm 9v Ym Fy"` to `"foobar"`::

       content:"/?arg=Zm 9v Ym Fy"; from_base64: offset 6, mode rfc2045; \
       content:"foobar";

.. _lua-transform:

luaxform
--------

This transform allows a Lua script to apply a transformation
to a buffer.

Lua scripts that are used for transformations *must* contain a function
named ``transform``.

Lua scripts can have other functions; Suricata only invokes the ``transform`` function.

Lua transforms can be passed optional arguments -- see the examples below -- but they
are not required to do so. Arguments are comma-separated.

A Lua transform function is not invoked if the buffer is empty or the Lua framework is
not accessible (rare).

Lua transform functions must return two values (see below) or the buffer is not modified.

Note that the arguments and values are passed without validation
nor interpretation. There is a maximum of 10 arguments.

The Lua transform function is invoked with these parameters:

  * `input` The buffer provided to the transform
  * `arguments` The list of arguments.

Lua transform functions must return two values [Lua datatypes shown]:

  * `buffer` [Lua string] The return buffer containing the original input buffer or buffer modified by the transform.
  * `bytes` [Lua integer] Number of bytes in return buffer.

This example supplies the HTTP data to a Lua transform and the transform
results are checked with `content`.

Example::

    alert http any any -> any any (msg:"Lua Xform example"; flow:established;  \
            file.data; luaxform:./lua/lua-transform.lua; content: "abc"; sid: 2;)


This example supplies the HTTP data to a Lua transform with with arguments
that specify the offset and byte count for the transform. The resulting
buffer is then checked with a `content` match.

Example::

    alert http any any -> any any (msg:"Lua Xform example"; flow:established; \
            file.data; luaxform:./lua/lua-transform.lua, bytes 12, offset 13; content: "abc"; sid: 1;)


The following Lua script shows a transform that handles arguments: `bytes` and `offset` and uses
those values (or defaults, if there are no arguments) for applying the uppercase transform to
the buffer.

.. code-block:: lua

   local function get_value(item, key)
       if string.find(item, key) then
           local _, value = string.match(item, "(%a+)%s*(%d*)")
           if value ~= "" then
               return tonumber(value)
           end
       end

       return nil
   end

   -- Arguments supported
   local bytes_key = "bytes"
   local offset_key = "offset"
   function transform(input_len, input, argc, args)
       local bytes = #input
       local offset = 0

       -- Look for optional bytes and offset arguments
       for i, item in ipairs(args) do
           local value = get_value(item, bytes_key)
           if value ~= nil then
               bytes = value
           else
               local value = get_value(item, offset_key)
               if value ~= nil then
                   offset = value
               end
           end
       end
       local str_len = #input
       if offset < 0 or offset > str_len then
           print("offset is out of bounds: " .. offset)
           return nil
       end
       str_len = str_len - offset
       if bytes < 0 or bytes > str_len then
           print("invalid bytes " ..  bytes .. " or bytes > length " .. bytes .. " length " .. str_len)
           return nil
       end
       local sub = string.sub(input, offset + 1, offset + bytes)
       return string.upper(sub), bytes
   end
