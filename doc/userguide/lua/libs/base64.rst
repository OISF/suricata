Base64
------

Base64 functions are exposed to Lua scripts with the
``suricata.base64`` library. For example::

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

Encode a buffer with standard base64 encoding but don't include any
padding.

``decode_nopad(string)``
^^^^^^^^^^^^^^^^^^^^^^^^

Decode a base64 string that contains no padding.

``decode_padopt(string)``
^^^^^^^^^^^^^^^^^^^^^^^^^

Decode a base64 string that may or may not contain trailing padding.

``decode_rfc2045(string)``
^^^^^^^^^^^^^^^^^^^^^^^^^^

Decode an RFC 2045 formatted base64 string.

``decode_rfc4648(string)``
^^^^^^^^^^^^^^^^^^^^^^^^^^

Decode an RFC 4648 formatted base64 string.

Implementation Details
~~~~~~~~~~~~~~~~~~~~~~

The base64 functions provided come from the Rust base64 library
documented at https://docs.rs/base64 and correspond to the
``STANDARD`` and ``STANDARD_NO_PAD`` base64 engines provided in that
library.
