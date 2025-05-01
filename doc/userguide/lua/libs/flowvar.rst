Flowvar
#######

The ``suricata.flowvar`` library exposes flow variables to Lua
scripts.

Initialization
--------------

First, the ``flowvar`` lib module must be loaded::

  local flowvarlib = require("suricata.flowvar")

Then in the ``init`` method, any flow variables used in the script
should be registered. This is optional and could be skipped if you
know for sure the flow variable will be registered by some other
means.

Example::

  local flowvarlib = require("suricata.flowvar")

  function init ()
      flowvarlib.register("count")
      return {}
  end

Finally, in the ``thread_init`` function a handle is acquired for the
flow variables and stored as a global::

  function thread_init ()
      count_flow_var = flowvarlib.get("count")
  end

Flow Variable Methods
---------------------

``value()``
^^^^^^^^^^^

Get the current value of the flow variable as a string. Note that
``nil`` may be returned if the flow variable does not have a value.

``set(value, len)``
^^^^^^^^^^^^^^^^^^^

Set the value of the flow variable to the value provided. The length
of the value must also be provided.

Example
-------

::

  local flowvarlib = require("suricata.flowvar")

  function init ()
      flowvarlib.register("count")
      return {}
  end

  function thread_init ()
      count_var = flowvarlib.get("count")
  end

  function match ()
      local value = count_var:value()
      if value == nil then
          -- Initialize value to 1.
          value = tostring(1)
          count_var:set(value, #value)
      else
          value = tostring(tonumber(value) + 1)
          count_var:set(value, #value)
      fi

      -- Return 1 or 0 based on your own logic.
      return 1
  end
