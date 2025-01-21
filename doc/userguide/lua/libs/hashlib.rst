Hashing
-------

Hashing functions are exposed to Lua scripts with ``suricata.hashing``
library. For example::

  local hashing = require("suricata.hashing")

SHA-256
~~~~~~~

``sha256_digest(string)``
^^^^^^^^^^^^^^^^^^^^^^^^^

SHA-256 hash the provided string returning the digest as bytes.

``sha256_hex_digest(string)``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

SHA-256 hash the provided string returning the digest as a hex string.

``sha256()``
^^^^^^^^^^^^

Returns a SHA-256 hasher that can be updated multiple times, for
example::

  local hashing = require("suricata.hashing")
  hasher = hashing.sha256()
  hasher.update("www.suricata")
  hasher.update(".io")
  hash = hasher.finalize_to_hex()

The methods on the hasher object include:

* ``update(string)``: Add more data to the hasher
* ``finalize()``: Finalize the hash returning the hash as a byte string
* ``finalize_to_hex()``: Finalize the hash returning the has as a hex string

SHA-1
~~~~~

``sha1_digest(string)``
^^^^^^^^^^^^^^^^^^^^^^^

SHA-1 hash the provided string returning the digest as bytes.

``sha1_hex_digest(string)``
^^^^^^^^^^^^^^^^^^^^^^^^^^^

SHA-1 hash the provided string returning the digest as a hex string.

``sha1()``
^^^^^^^^^^

Returns a SHA-1 hasher that can be updated multiple times, for
example::

  local hashing = require("suricata.hashing")
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

``md5_hex_digest(string)``
^^^^^^^^^^^^^^^^^^^^^^^^^^

MD5 hash the provided string returning the digest as a hex string.

``md5()``
^^^^^^^^^

Returns a MD5 hasher that can be updated multiple times, for example::

  local hashing = require("suricata.hashing")
  hasher = hashing.md5()
  hasher.update("www.suricata")
  hasher.update(".io")
  hash = hasher.finalize_to_hex()

The methods on the hasher object include:

* ``update(string)``: Add more data to the hasher
* ``finalize()``: Finalize the hash returning the hash as a byte string
* ``finalize_to_hex()``: Finalize the hash returning the hash as a hex string
