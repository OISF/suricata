XOR keywords
===============

Suricata supports decrypting xor encrypted data from buffers and matching on the
decrypted data.

This is achieved by using two keywords, ``xor`` and ``xor_data``. Both keywords
must be used in order to generate an alert.

xor
-------------

Decrypts xor data from a buffer and makes it available for the ``xor_data``
keyword.

Syntax::

  xor: key ("<hex string>"|<variable>)[, bytes <num of bytes>] \
  [, offset <offset>][, relative];

``key`` is the only required option and specifies the xor decryption key to use.
Either a hex string in double-quotes or a ``byte_extract`` variable without
quotes may be used as a key.

The ``bytes`` option specifies the number of bytes Suricata should decrypt and
make available to ``xor_data``. Suricata will decrypt until the end of the
buffer if ``bytes`` is not provided. Fewer than the specified number of bytes
may be decrypted if the end of the buffer is reached.

The ``offset`` option specifies the number of bytes Suricata should skip before
decrypting. Bytes are skipped relative to the start of the buffer if the
``relative`` option is not set.

The ``relative`` option makes decryption start relative to the previous content
match. Default behavior is to start at the beginning of the buffer. This option
makes ``offset`` skip bytes relative to the previous match.

.. note:: Regarding ``relative`` and ``xor``:

    The content match that you want to decode relative to must be the first
    match in the stream.

xor_data
-----------

``xor_data`` is a ``sticky buffer``.

Enables content matching on the data previously decrypted by ``xor``.

Examples
-----------

Sticky Buffer Example
+++++++++++++++++++++++++

Here is an example of a rule matching on xor decrypted data found inside the
``http.request_body`` buffer using the known static key ``0d0ac8``.

Decrypting starts at the beginning of the ``http.request_body`` buffer and will
process up to 133 bytes. It will only do decryption if the content
``fast_pattern`` matches, saving processing time.

``http.request_body`` buffer content::

    00000000  4a 2f fb 3c 2f fb 3f 2f  fb 3b 4e ed 3e 32 ed 3e
    00000010  3a ed 3e 38 ed 3f 4e ed  3e 3b ed 3e 39 ed 3e 3e
    00000020  ed 3e 39 89 28 39 fa 48  49 ed 3f 4e ed 3e 3c ed
    00000030  3e 3b ed 3e 3c 8c 28 39  f8 4b 49 8e 28 38 8c 28
    00000040  39 fa 4b 2f fb 3a 4b ed  3e 3f ed 3e 3b ed 3e 33
    00000050  ed 3e 33 ed 3f 4e ed 3e  38 ed 3e 33 ed 3e 3e ed
    00000060  3e 32 ed 3e 38 ed 3e 3c  8c 28 39 fd 4b

Rule::

    alert http any any -> any any (msg:"Example"; http.method; content:"POST"; \
        http.uri; content:".php"; endswith; \
        http.request_body; content:"|4a 2f fb|"; fast_pattern; startswith; \
        xor: key "0d0ac8", bytes 133, offset 0; \
        xor_data; pcre:"/^G(?:[A-F]|%3[0-9]){7}%2D(?:[A-F]|%3[0-9]){8}%2D(?:[A-F]|%3[0-9]){8}%2D(?:[A-F]|%3[0-9]){8}%2D(?:[A-F]|%3[0-9]){9}$/"; \
        sid:1; rev:1;)

``xor_data`` decrypted buffer content::

    00000000  47 25 33 31 25 33 32 25 33 36 44 25 33 38 25 33  |G%31%32%36D%38%3|
    00000010  30 25 33 32 25 32 44 25 33 31 25 33 33 25 33 34  |0%32%2D%31%33%34|
    00000020  25 33 33 41 25 33 32 45 43 25 32 44 25 33 36 25  |%33A%32EC%2D%36%|
    00000030  33 31 25 33 36 44 25 33 30 46 43 46 25 32 44 25  |31%36D%30FCF%2D%|
    00000040  33 32 46 25 33 37 41 25 33 35 25 33 31 25 33 39  |32F%37A%35%31%39|
    00000050  25 33 39 25 32 44 25 33 32 25 33 39 25 33 34 25  |%39%2D%32%39%34%|
    00000060  33 38 25 33 32 25 33 36 44 25 33 35 46           |38%32%36D%35F|

Byte Extraction Example
+++++++++++++++++++++++++

This example uses ``byte_extract`` to extract the xor key from the payload
buffer itself. It will extract 3 bytes after the content match on ``|be ef|``
into the variable ``xor_key`` (i.e. ``b2259a``). Afterwards, it will decrypt
the bytes following the xor key until the end of the payload buffer. Finally,
a content match will occur on the decrypted bytes.

Payload buffer content hexdump::

    00000000  ff ff ff ff ff ff ff ff  ff be ef b2 25 9a ce 07
    00000010  d4 47 5d 51 4a 4c 01 02  03 04 01 02 03 04

Rule::

    alert tcp any any -> any any (
        msg: "Example";
        content: "|be ef|";
        byte_extract: 3, 0, xor_key, relative;
        xor: key xor_key, relative;
        xor_data; content: "|7c 22 4e|"; startswith;
        sid:1; rev:1;)

``xor_data`` decrypted buffer content hexdump::

    00000000  7c 22 4e f5 78 cb f8 69  9b b0 26 9e b3 27 99 b6
