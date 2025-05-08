File
####

File information is exposed to Lua scripts with the ``suricata.file``
library, for example::

  local filelib = require("suricata.file")

Setup
*****

If your purpose is to create a logging script, initialize the script
as:

::

  function init (args)
     local needs = {}
     needs["type"] = "file"
     return needs
  end

Currently the Lua file library is not implemented for rules.

API
***

File Object
===========

File data is accessed through the file object, which must be
obtained before use::

  local file, err = filelib.get_file()
  if file == nil then
      print(err)
  end

File Methods
============

``file_id()``
-------------

Returns the ID number of the file.

Example::

  local file = filelib.get_file()
  local id = file:file_id()
  print("File ID: " .. id)

``tx_id()``
-----------

Returns the transaction ID associated with the file.

Example::

  local file = filelib.get_file()
  local tx_id = file:tx_id()
  print("Transaction ID: " .. tx_id)

``name()``
----------

Returns the file name.

Example::

  local file = filelib.get_file()
  local name = file:name()
  if name ~= nil then
      print("Filename: " .. name)
  end

``size()``
----------

Returns the file size.

Example::

  local file = filelib.get_file()
  local size = file:size()
  print("File size: " .. size .. " bytes")

``magic()``
-----------

Returns the file type based on libmagic (if available). Will return
nil if magic is not available.

Example::

  local file = filelib.get_file()
  local magic = file:magic()
  if magic ~= nil then
      print("File type: " .. magic)
  end

``md5()``
---------

Returns the MD5 hash of the file (if calculated). Will return nil if
the MD5 hash was not calculated.

Example::

  local file = filelib.get_file()
  local md5 = file:md5()
  if md5 ~= nil then
      print("MD5: " .. md5)
  end

``sha1()``
----------

Returns the SHA1 hash of the file (if calculated). Will return nil if
the SHA1 hash was not calculated.

Example::

  local file = filelib.get_file()
  local sha1 = file:sha1()
  if sha1 ~= nil then
      print("SHA1: " .. sha1)
  end

``sha256()``
------------

Returns the SHA256 hash of the file (if calculated). Will return nil
if the SHA256 hash was not calculated.

Example::

  local file = filelib.get_file()
  local sha256 = file:sha256()
  if sha256 ~= nil then
      print("SHA256: " .. sha256)
  end

``get_state()``
---------------

Returns the current state of the file.

Returns:

- State: "CLOSED", "TRUNCATED", "ERROR", "OPENED", "NONE", or
    "UNKNOWN"

Example::

  local file = filelib.get_file()
  local state = file:get_state()
  if state ~= nil then
      print("File state: " .. state)
  end

``is_stored()``
---------------

Returns true if the file has been stored to disk, false otherwise.

Example::

  local file = filelib.get_file()
  local stored = file:is_stored()
  print("File stored: " .. tostring(stored))
