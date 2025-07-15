.. _lua-functions:

Lua functions
=============

Differences between `output` and `detect`:
------------------------------------------

Currently, the ``needs`` key initialization varies, depending on what is the goal of the script: output or detection.
The Lua script for the ``luaxform`` transform **does not use ``needs``**.

If the script is for detection, the ``needs`` initialization should be as seen in the example below (see :ref:`lua-detection` for a complete example of a detection script):

::

  function init (args)
      local needs = {}
      needs["packet"] = tostring(true)
      return needs
  end

For output logs, follow the pattern below. (The complete script structure can be seen at :ref:`lua-output`:)

::

  function init (args)
      local needs = {}
      needs["protocol"] = "tls"
      return needs
  end


Do notice that the functions and protocols available for ``log`` and ``match`` may also vary. DNP3, for instance, is not
available for logging.

packet
------

Initialize with:

::

  function init (args)
      local needs = {}
      needs["type"] = "packet"
      return needs
  end


flow
----

::

  function init (args)
      local needs = {}
      needs["type"] = "flow"
      return needs
  end

http
----

For output, init with:

::

  function init (args)
      local needs = {}
      needs["protocol"] = "http"
      return needs
  end

For detection, use the specific buffer (cf :ref:`lua-detection` for a complete list), as with:

::

  function init (args)
      local needs = {}
      needs["http.uri"] = tostring(true)
      return needs
  end

Streaming Data
--------------

Streaming data can currently log out reassembled TCP data and
normalized HTTP data. The script will be invoked for each consecutive
data chunk.

In case of TCP reassembled data, all possible overlaps are removed
according to the host OS settings.

::

  function init (args)
      return {streaming = "tcp"}
  end

In case of HTTP body data, the bodies are unzipped and dechunked if applicable.

::

  function init (args)
      return {streaming = "http"}
  end

The streaming data will be provided in the ``args`` to the log
function within a ``stream`` subtable::

  function log(args)
    -- The data (buffer)
    local data = args["stream"]["data"]

    -- Buffer open?
    local open = args["stream"]["open"]

    -- Buffer closed?
    local close = args["stream"]["close"]

    -- To server?
    local ts = args["stream"]["to_server"]

    -- To client?
    local tc = args["stream"]["to_client"]
  end
