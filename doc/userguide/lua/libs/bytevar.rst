Bytevar
#######

The ``suricata.bytevar`` module provides access to variables defined by 
``byte_extract`` and ``byte_math`` keywords in Suricata rules. 

It is only available in Suricata Lua rules, not output scripts.

Setup
*****

::

    local bytevars = require("suricata.bytevar")

Module Functions
****************

.. function:: bytevars.map(sig, varname)

   Ensures that the ``bytevar`` exists and sets it up for further use
   in the script by mapping it into the Lua context. Must be called
   during ``init()``.

   :param sig: The signature object passed to ``init()``
   :param string varname: Name of the variable as defined in the rule

   :raises error: If the variable name is unknown
   :raises error: If too many byte variables are mapped

   Example:

   ::

       function init(sig)
           bytevars.map(sig, "var1")
           bytevars.map(sig, "var2")
           return {}
       end

.. function:: bytevars.get(name)

   Returns a byte variable object for the given name. May be called
   during ``thread_init()`` to save a handle to the bytevar.

   :param number name: Name of the variable previously setup with
                       ``map()``.

   :raises error: If variable name is not mapped with ``map()``.

   :returns: A byte variable object

   Example:

   ::

       function thread_init()
           bv_var1 = bytevars.get("var1")
           bv_var2 = bytevars.get("var2")
       end

Byte Variable Object Methods
****************************

.. method:: bytevar:value()

   Returns the current value of the byte variable.

   :returns: The value of the byte variable.

   Example:

   ::

       function match(args)
           local var1 = bv_var1:value()
           if var1 then
               -- Use the value
           end
       end
