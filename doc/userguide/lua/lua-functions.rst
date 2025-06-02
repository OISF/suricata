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

HttpGetRequestBody and HttpGetResponseBody.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Make normalized body data available to the script through
HttpGetRequestBody and HttpGetResponseBody.

There no guarantees that all of the body will be available.

Example:

::

  function log(args)
      a, o, e = HttpGetResponseBody();
      --print("offset " .. o .. " end " .. e)
      for n, v in ipairs(a) do
          print(v)
      end
  end

HttpGetRequestHost
~~~~~~~~~~~~~~~~~~

Get the host from libhtp's htp_tx_request_hostname(tx), which can either be
the host portion of the url or the host portion of the Host header.

Example:

::

  http_host = HttpGetRequestHost()
  if http_host == nil then
      http_host = "<hostname unknown>"
  end

HttpGetRequestHeader
~~~~~~~~~~~~~~~~~~~~

::

  http_ua = HttpGetRequestHeader("User-Agent")
  if http_ua == nil then
      http_ua = "<useragent unknown>"
  end

HttpGetResponseHeader
~~~~~~~~~~~~~~~~~~~~~

::

  server = HttpGetResponseHeader("Server");
  print ("Server: " .. server);

HttpGetRequestLine
~~~~~~~~~~~~~~~~~~

::

  rl = HttpGetRequestLine();
  print ("Request Line: " .. rl);

HttpGetResponseLine
~~~~~~~~~~~~~~~~~~~

::

  rsl = HttpGetResponseLine();
  print ("Response Line: " .. rsl);

HttpGetRawRequestHeaders
~~~~~~~~~~~~~~~~~~~~~~~~

::

  rh = HttpGetRawRequestHeaders();
  print ("Raw Request Headers: " .. rh);

HttpGetRawResponseHeaders
~~~~~~~~~~~~~~~~~~~~~~~~~

::

  rh = HttpGetRawResponseHeaders();
  print ("Raw Response Headers: " .. rh);

HttpGetRequestUriRaw
~~~~~~~~~~~~~~~~~~~~

::

  http_uri = HttpGetRequestUriRaw()
  if http_uri == nil then
      http_uri = "<unknown>"
  end

HttpGetRequestUriNormalized
~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

  http_uri = HttpGetRequestUriNormalized()
  if http_uri == nil then
      http_uri = "<unknown>"
  end

HttpGetRequestHeaders
~~~~~~~~~~~~~~~~~~~~~

::

  a = HttpGetRequestHeaders();
  for n, v in pairs(a) do
      print(n,v)
  end

HttpGetResponseHeaders
~~~~~~~~~~~~~~~~~~~~~~

::

  a = HttpGetResponseHeaders();
  for n, v in pairs(a) do
      print(n,v)
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
    local ts = args["stream"]["toserver"]

    -- To client?
    local tc = args["stream"]["toclient"]
  end

Flow variables
--------------

It is possible to access, define and modify Flow variables from Lua. To do so,
you must use the functions described in this section and declare the counter in
init function:

::

 function init(args)
     local needs = {}
     needs["tls"] tostring(true)
     needs["flowint"] = {"tls-cnt"}
     return needs
 end

Here we define a `tls-cnt` Flowint that can now be used in output or in a
signature via dedicated functions. The access to the Flow variable is done by
index so in our case we need to use 0.

::

 function match(args)
     a = SCFlowintGet(0);
     if a then
         SCFlowintSet(0, a + 1)
     else
         SCFlowintSet(0, 1)
     end

SCFlowintGet
~~~~~~~~~~~~

Get the Flowint at index given by the parameter.

SCFlowintSet
~~~~~~~~~~~~

Set the Flowint at index given by the first parameter. The second parameter is the value.

SCFlowintIncr
~~~~~~~~~~~~~

Increment Flowint at index given by the first parameter.

SCFlowintDecr
~~~~~~~~~~~~~

Decrement Flowint at index given by the first parameter.
