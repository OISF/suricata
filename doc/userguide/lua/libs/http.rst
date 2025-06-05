HTTP
----

HTTP transaction details are exposes to Lua scripts with the
``suricata.http`` library, For example::

  local http = require("suricata.http")

Setup
^^^^^

If your purpose is to create a logging script, initialize the buffer as:

::

  function init (args)
     local needs = {}
     needs["protocol"] = "http"
     return needs
  end

If you are going to use the script for rule matching, choose one of
the available HTTP buffers listed in :ref:`lua-detection` and follow
the pattern:

::

  function init (args)
     local needs = {}
     needs["http.request_line"] = tostring(true)
     return needs
  end

Transaction
~~~~~~~~~~~

HTTP is transaction based, and the current transaction must be obtained before use::

  local tx, err = http.get_tx()
  if tx == err then
      print(err)
  end

All other functions are methods on the transaction table.

Transaction Methods
~~~~~~~~~~~~~~~~~~~

``request_header()``
^^^^^^^^^^^^^^^^^^^^

Get the HTTP request header value by key.

Example::

  local tx = http.get_tx()
  local ua = tx:request_header("User-Agent")
  if ua ~= nil then
        print(ua)
  end

``response_header()``
^^^^^^^^^^^^^^^^^^^^^

Get the HTTP response header value by key.

Example::

  local tx = http.get_tx()
  local content_type = tx:response_header("Content-Type")
  if content_type ~= nil then
        print(content_type)
  end

``request_line``
^^^^^^^^^^^^^^^^

Get the HTTP request line as a string.

Example::

  local tx = http.get_tx()
  local http_request_line = tx:request_line();
  if #http_request_line > 0 then
      if http_request_line:find("^GET") then
          print(http_request_line)
      end
  end

``response_line``
^^^^^^^^^^^^^^^^^

Get the HTTP response line as a string.

Example::

  local tx = http.get_tx()
  local http_response_line = tx:response_line();
  if #http_response_line > 0 then
        print(http_response_line)
  end

``request_headers_raw()``
^^^^^^^^^^^^^^^^^^^^^^^^^

Get the raw HTTP request headers.

Example::

  http_request_headers_raw = tx:request_headers_raw()

  if #http_request_headers_raw > 0 then
      if http_request_headers_raw:find("User%-Agent: curl") then
          print(http_request_headers_raw)
      end
  end

``response_headers_raw()``
^^^^^^^^^^^^^^^^^^^^^^^^^^

Get the raw HTTP response headers.

Example::

  http_response_headers_raw = tx:response_headers_raw()

  if #http_response_headers_raw > 0 then
        print(http_response_headers_raw)
  end

``request_uri_raw()``
^^^^^^^^^^^^^^^^^^^^^

Get the raw HTTP request URI.

Example::

  local tx = http.get_tx()
  http_request_uri_raw = tx:request_uri_raw()
  print(http_request_uri_raw)

``request_uri_normalized()``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Get the normalized HTTP request URI.

Example::

  local tx = http.get_tx()
  http_request_uri_normalized = tx:request_uri_normalized()
  print(http_request_uri_normalized)

``request_headers()``
^^^^^^^^^^^^^^^^^^^^^

Get the HTTP request headers.

Example::

  local tx = http.get_tx()
  http_request_headers = tx:request_headers()
  print(http_request_headers)

``response_headers()``
^^^^^^^^^^^^^^^^^^^^^^

Get the HTTP response headers.

Example::

  local tx = http.get_tx()
  http_response_headers = tx:response_headers()
  print(http_response_headers)

``request_body()``
^^^^^^^^^^^^^^^^^^

Get the HTTP request body.

Example::

  local tx = http.get_tx()
  http_request_body = tx:request_body()
  print(http_request_body)

``response_body()``
^^^^^^^^^^^^^^^^^^^

Get the HTTP response body.

Example::

  local tx = http.get_tx()
  http_response_body = tx:response_body()
  print(http_response_body)

``request_host()``
^^^^^^^^^^^^^^^^^^

Get the HTTP request host.

Example::

  local tx = http.get_tx()
  http_host = tx:request_host()
  print(http_host)

