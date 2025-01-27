Base64
------

Base64 functions are expose to Lua scripts with the
``suricata.base64``. For example::

  local base64 = require("suricata.base64")

Functions
~~~~~~~~~

``encode(string)``
^^^^^^^^^^^^^^^^^^

Encode a buffer with standard base64 encoding. This standard encoding
includes padding.

``decode(string)``
^^^^^^^^^^^^^^^^^^

Decode a base64 string that contains padding.

``encode_nopad(string)``
^^^^^^^^^^^^^^^^^^^^^^^^

Encode a buffer with standard base64 encoded but don't include any
padding.

``decode_nopad(string)``
^^^^^^^^^^^^^^^^^^^^^^^^

Decode a base64 buffer that contains no padding.

Implementation Details
~~~~~~~~~~~~~~~~~~~~~~

The base64 functions provided come from the Rust base64 library
documented at https://docs.rs/base64 and corresponse to the
``STANDARD`` and ``STANDARD_NO_PAD`` base64 engines provided in that
library.
