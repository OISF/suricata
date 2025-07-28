.. _lua-functions:

Lua functions
=============

Differences between `output` and `detect`:
------------------------------------------

Currently the ``table`` returned from the ``init`` method varies,
depending on whether it is in an output script or a detection script.

Lua scripts for ``luaxform`` do not require an ``init`` method.

If the script is for detection, the ``init`` method should return a
table, for example, if a packet is required:

.. code-block:: lua

  function init (args)
    local needs = {}
    needs["packet"] = true
    return needs
  end

See :ref:`lua-detection` for more detection script examples.

For output scripts, follow the pattern below. (The complete script
structure can be seen at :ref:`lua-output`:)

.. code-block:: lua

  function init (args)
      local needs = {}
      needs["protocol"] = "tls"
      return needs
  end

Do notice that the functions and protocols available for ``log`` and
``match`` may also vary. DNP3, for instance, is not available for
logging.

.. note:: By convention, many scripts use a variable name of ``needs``
          for this table, however this is not a hard requirement.

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

For detection, rule hooks are used to execute the Lua script at
specific protocol states, for example::

  alert http1:request_line any any -> any any (
      msg: "Test HTTP Lua request.line";
      lua: test-request-line.lua; sid:1;)

where ``test-request-line.lua`` might look like:

.. code-block:: lua

  local http = require("suricata.http")

  function init (args)
    return {}
  end

  function match(args)
    local tx, err = http.get_tx()
    http_request_line, err = tx:request_line()

    if #http_request_line > 0 then
        --GET /base64-hello-world.txt HTTP/1.1
        if http_request_line:find("^GET") then
            return 1
        end
    end

    return 0
  end

For more information on rule hooks, see :ref:`rule-hooks`.

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
