.. _lua-detection:

Lua Scripting for Detection
===========================

.. note:: Lua is disabled by default for use in rules, it must be
          enabled in the configuration file. See the ``security.lua``
          section of ``suricata.yaml`` and enable ``allow-rules``.

Syntax:

::

  lua:[!]<scriptfilename>;

The script filename will be appended to your default rules location.

A Lua rule script has 2 required functions, an ``init`` function and
``match`` function, discussed below.

Additionally, the script will run in a limited sandbox by default.

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
* buffer -- the current sticky buffer
* stream
* dnp3
* dns.request
* dns.response
* dns.rrname
* ssh
* smtp
* tls
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

Sandbox and Available functions
-------------------------------

Lua rule scripts are run in a sandbox environment the applies the
following restrictions:

* reduced libraries
* only allowed functions available
* instruction count limit
* memory allocation limit

The following table lists the library and functions available:

==================  =================================================================
Package Name        Functions
==================  =================================================================
base                assert, ipairs, next, pairs, print, rawequal, rawlen, select, 
                    tonumber, tostring, type, warn, rawget, rawset, error
table               concat, insert, move, pack, remove, sort, unpack
string              byte, char, dump, find, format, gmatch, gsub, len, lower, match, 
                    pack, packsize, rep, reverse, sub, unpack, upper
math                abs, acos, asin, atan, atan2, ceil, cos, cosh, deg, exp, floor, 
                    fmod, frexp, ldexp, log, log10, max, min, modf, pow, rad, random, 
                    randomseed, sin, sinh, sqrt, tan, tanh, tointeger, type, ult
utf8                offset, len, codes, char, codepoint
==================  =================================================================

Of note, the following standard libraries are not available:

* coroutine
* package
* input and output
* operating system facilities
* debug

This behavior can be modified via the ``security.lua`` section of :ref:`suricata-yaml-lua-config`

.. note:: Suricata 8.0 has moved to Lua 5.4 and has builtin support for bitwise and utf8 operations now.

A comprehensive list of existing lua functions - with examples - can
be found at :ref:`lua-functions` (some of them, however, work only for
the lua-output functionality).
