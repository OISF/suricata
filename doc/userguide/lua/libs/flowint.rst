Flowint Library
###############

The ``suricata.flowint`` library exposes ``flowint`` variables to Lua
scripts.

Initialization
**************

First, the ``flowint`` module must be loaded::

  local flowintlib = require("suricata.flowint")

Then in the ``init`` method, any flow integers used in the script
should be registered. This is optional and could be skipped if you
know for sure the flow integers will be registered by some other
means.

Example::

  local flowintlib = require("suricata.flowint")

  function init ()
      flowintlib.register("count")
      return {}
  end

Finally, in the ``thread_init`` function a handle is acquired for the
flow integers and stored as a global::

  function thread_init ()
      count_flow_int = flowintlib.get("count")
  end

Flow Integer Methods
********************

``decr()``
==========

Decrement the value of the ``flowint`` by 1. The new value is
returned. If the value is 0, it will remain 0.

``incr()``
==========

Increment the value of the ``flowint`` by 1. The new value is
returned.

``value()``
===========

Get the current value of the flow integer. Note that ``nil`` may be
returned if the flow integer does not have a value.

``set(value)``
===================

Set the value of the flowint to the value provided.
