Lua usage in Suricata
=====================

Lua scripting can be used in two components of Suricata:

  * Output
  * Detection: ``lua`` keyword and ``luaxform`` transform

Both features are using a list of functions to access the data extracted by
Suricata. You can get the list of functions in the :ref:`lua-functions` page.

.. note:: Currently, there is a difference in the ``needs`` key in the ``init`` function,
   depending on what is the usage: ``output`` or ``detection``. The list of available
   functions may also differ. The ``luaxform`` doesn't use the ``needs`` key.

Lua output
----------

Lua scripts can be used to write arbitrary output. See :ref:`lua-output` for more information.

Lua detection
-------------

Lua scripts can be used as a filter condition in signatures. See :ref:`lua-detection` for more information.

Lua transform
-------------

The ``luaxform`` transform can be used in signatures. See :ref:`lua-transform` for more information.
