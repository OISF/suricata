Hashing
-------

Hashing functions are exposed to Lua scripts with ``suricata.hashlib``
library. For example::

  local hashing = require("suricata.hashlib")

If ``--disable-hashing`` is set, every hashlib call raises a Lua error
instead of computing a digest, consistent with the hashing transforms
and JA3/JA4. Inputs of 4 GiB (2 to the 32nd bytes) or more are
rejected, matching the 32-bit length the FFI takes.

SHA-256
~~~~~~~

``sha256_digest(string)``
^^^^^^^^^^^^^^^^^^^^^^^^^

SHA-256 hash the provided string returning the digest as bytes.

``sha256_hexdigest(string)``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

SHA-256 hash the provided string returning the digest as a hex string.

``sha256()``
^^^^^^^^^^^^

Returns a SHA-256 hasher that can be updated multiple times, for
example::

  local hashing = require("suricata.hashlib")
  hasher = hashing.sha256()
  hasher:update("www.suricata")
  hasher:update(".io")
  hash = hasher:finalize_to_hex()

The methods on the hasher object include:

* ``update(string)``: Add more data to the hasher
* ``finalize()``: Finalize the hash returning the hash as a byte string
* ``finalize_to_hex()``: Finalize the hash returning the has as a hex string

SHA-1
~~~~~

``sha1_digest(string)``
^^^^^^^^^^^^^^^^^^^^^^^

SHA-1 hash the provided string returning the digest as bytes.

``sha1_hexdigest(string)``
^^^^^^^^^^^^^^^^^^^^^^^^^^^

SHA-1 hash the provided string returning the digest as a hex string.

``sha1()``
^^^^^^^^^^

Returns a SHA-1 hasher that can be updated multiple times, for
example::

  local hashing = require("suricata.hashlib")
  hasher = hashing.sha1()
  hasher.update("www.suricata")
  hasher.update(".io")
  hash = hasher.finalize_to_hex()

The methods on the hasher object include:

* ``update(string)``: Add more data to the hasher
* ``finalize()``: Finalize the hash returning the hash as a byte string
* ``finalize_to_hex()``: Finalize the hash returning the has as a hex string

MD5
~~~

``md5_digest(string)``
^^^^^^^^^^^^^^^^^^^^^^

MD5 hash the provided string returning the digest as bytes.

``md5_hexdigest(string)``
^^^^^^^^^^^^^^^^^^^^^^^^^^

MD5 hash the provided string returning the digest as a hex string.

``md5()``
^^^^^^^^^

Returns a MD5 hasher that can be updated multiple times, for example::

  local hashing = require("suricata.hashlib")
  hasher = hashing.md5()
  hasher:update("www.suricata")
  hasher:update(".io")
  hash = hasher:finalize_to_hex()

The methods on the hasher object include:

* ``update(string)``: Add more data to the hasher
* ``finalize()``: Finalize the hash returning the hash as a byte string
* ``finalize_to_hex()``: Finalize the hash returning the hash as a hex string
