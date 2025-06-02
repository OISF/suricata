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

.. function:: bytevars.ensure(sig, varname)

   Ensures that the ``bytevar`` exists and sets it up for further use
   in the script. Must be called during ``init()``.

   :param sig: The signature object passed to ``init()``
   :param string varname: Name of the variable as defined in the rule

   :raises error: If the variable name is unknown
   :raises error: If too many byte variables are registered

   Example:

   ::

       function init(sig)
           bytevars.ensure(sig, "var1")
           bytevars.ensure(sig, "var2")
           return {}
       end

.. function:: bytevars.get(index)

   Returns a byte variable object for the given index. May be called
   during ``thread_init()`` to save a handle to the bytevar.

   :param number index: Zero-based index of the variable (in order of
                        ``ensure()`` calls)
   :returns: A byte variable object

   Example:

   ::

       function thread_init()
           bv_var1 = bytevars.get(0)
           bv_var2 = bytevars.get(1)
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
