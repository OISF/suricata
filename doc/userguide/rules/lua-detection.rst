.. _lua-detection:

Lua Scripting for Detection
===========================

There are 2 ways that Lua can be used with detection. These are

* ``lua`` rule keyword.
* ``luaxform`` transform.

.. note:: As of Suricata 8.0, Lua rules are enabled by default and run
          in a sandboxed environment. See :ref:`lua-sandbox`.

Lua Rule Keyword
----------------

Syntax:

::

  lua:[!]<scriptfilename>;

The script filename will be appended to your default rules location.

A Lua rule script has 2 required functions, an ``init`` function and
``match`` function, discussed below.

Additionally, the script will run in a limited sandbox by default.

Init function
^^^^^^^^^^^^^

.. code-block:: lua

  function init (args)
      return {}
  end

Most Lua rule scripts can simply return an empty table in their init
method. To hook into specific protocols states, :ref:`rule-hooks` may
be used. However, some buffers do require explicit initialization::

* ja3
* ja3s
* packet
* payload
* stream

To request these buffers, use an ``init`` method like:

.. code-block:: lua

  function init (args)
    return {packet = true}
  end

Match function
^^^^^^^^^^^^^^

.. code-block:: lua

  local http = require("suricata.http")

  function match(args)
      local tx = http.get_tx()
      a = tx:request_line()
      if #a > 0 then
          if a:find("^POST%s+/.*%.php%s+HTTP/1.0$") then
              return 1
          end
      end

      return 0
  end

The script can return 1 or 0. It should return 1 if the condition(s)
it checks for match, 0 if not.

Lua Transform: ``luaxform``
---------------------------

More details in :ref:`lua-transform`.

.. _lua-sandbox:

Lua Sandbox and Available functions
-----------------------------------

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

.. note:: Suricata 8.0 has moved to Lua 5.4 and now has builtin support for bitwise and utf8 operations.

A comprehensive list of existing lua functions - with examples - can
be found at :ref:`lua-functions` (some of them, however, work only for
the lua-output functionality).
