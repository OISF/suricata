Lua Scripting
=============

Syntax:

::

  lua:[!]<scriptfilename>;

The script filename will be appended to your default rules location.

The script has 2 parts, an init function and a match function. First, the init.

Init function
-------------


.. code-block:: lua

  function init (args)
      local needs = {}
      needs["http.request_line"] = tostring(true)
      return needs
  end

The init function registers the buffer(s) that need
inspection. Currently the following are available:

* packet -- entire packet, including headers
* payload -- packet payload (not stream)
* http.uri
* http.uri.raw
* http.request_line
* http.request_headers
* http.request_headers.raw
* http.request_cookie
* http.request_user_agent
* http.request_body
* http.response_headers
* http.response_headers.raw
* http.response_body
* http.response_cookie

All the HTTP buffers have a limitation: only one can be inspected by a
script at a time.

Match function
--------------

.. code-block:: lua

  function match(args)
      a = tostring(args["http.request_line"])
      if #a > 0 then
          if a:find("^POST%s+/.*%.php%s+HTTP/1.0$") then
              return 1
          end
      end

      return 0
  end

The script can return 1 or 0. It should return 1 if the condition(s)
it checks for match, 0 if not.

Entire script:

.. code-block:: lua

  function init (args)
      local needs = {}
      needs["http.request_line"] = tostring(true)
      return needs
  end

  function match(args)
      a = tostring(args["http.request_line"])
      if #a > 0 then
          if a:find("^POST%s+/.*%.php%s+HTTP/1.0$") then
              return 1
          end
      end

      return 0
  end

  return 0
