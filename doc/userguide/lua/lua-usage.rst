Lua usage in Suricata
=====================

Lua scripting can be used in two components of Suricata. The first is in
output and the second one in rules in the detection engine.

Both features are using a list of functions to access the data extracted by
Suricata. You can get the list of functions in the :ref:`lua-functions` page.

.. note:: Currently, there is a difference in the ``needs`` key in the ``init`` function, depending on what is the usage: ``output`` or ``detection``. The list of available functions may also differ.

Lua output
----------

Lua can be used to write arbitrary output. See :ref:`lua-output` for more information.

Lua detection
-------------

Lua script can be used as a filter condition in signatures. See :ref:`lua-detection` for more information.
