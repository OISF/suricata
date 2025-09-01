DNP3
####

The ``suricata.dnp3`` module provides access to DNP3 (Distributed
Network Protocol 3) transaction data in Suricata Lua rules.

It is only available in Suricata Lua rules, not output scripts.

Setup
*****

::

    local dnp3 = require("suricata.dnp3")

Module Functions
****************

.. function:: dnp3.get_tx()

   Returns the current DNP3 transaction object containing request or response data.

   :returns: A table containing the DNP3 transaction data, or nil on error
   :raises error: If the protocol is not DNP3
   :raises error: If no transaction is available

   Example:

   ::

       function match(args)
           local tx = dnp3.get_tx()
           if tx and tx.is_request then
               -- Process DNP3 request
           end
       end

Transaction Object Structure
****************************

The transaction object returned by ``get_tx()`` contains the following fields:

.. attribute:: tx_num

   Transaction number (integer)

.. attribute:: is_request

   Boolean indicating if this is a request (true) or response (false)

.. attribute:: request

   Table containing request data (only present when ``is_request`` is true)

.. attribute:: response

   Table containing response data (only present when ``is_request`` is false)

Request/Response Structure
**************************

Both request and response tables contain:

.. attribute:: done

   Boolean indicating if the transaction is complete

.. attribute:: complete

   Boolean indicating if all data has been received

.. attribute:: link_header

   Table containing DNP3 link layer header fields:

   - ``len``: Frame length
   - ``control``: Control byte
   - ``dst``: Destination address
   - ``src``: Source address
   - ``crc``: CRC value

.. attribute:: transport_header

   Transport layer header byte (integer)

.. attribute:: application_header

   Table containing DNP3 application layer header fields:

   - ``control``: Application control byte
   - ``function_code``: DNP3 function code

.. attribute:: objects

   Array of DNP3 objects in the message

Additionally, response tables contain:

.. attribute:: indicators

   Internal Indication (IIN) field as a 16-bit integer combining IIN1 and IIN2

Objects Structure
*****************

Each object in the ``objects`` array contains:

.. attribute:: group

   DNP3 object group number (integer)

.. attribute:: variation

   DNP3 object variation number (integer)

.. attribute:: points

   Array of data points for this object

Points Structure
****************

Each point in the ``points`` array contains:

.. attribute:: index

   Point index (integer)

Additional point fields depend on the object group and variation. Common fields include:

- ``state``: Binary state value
- ``online``: Online status flag
- ``restart``: Restart flag
- ``comm_lost``: Communication lost flag
- ``remote_forced``: Remote forced flag
- ``local_forced``: Local forced flag
- ``chatter_filter``: Chatter filter flag
- ``reserved``: Reserved bits
- ``value``: Analog value (for analog objects)
- ``timestamp``: Timestamp value (for time-tagged objects)

For all available fields, see ``app-layer-dnp3-objects.h`` in the
Suricata source code.

Example Usage
*************

Complete example checking for specific DNP3 function codes:

::

    local dnp3 = require("suricata.dnp3")

    function init(args)
        return {}
    end

    function match(args)
        local tx = dnp3.get_tx()
        
        if not tx then
            return 0
        end
        
        -- Check for write function code in request
        if tx.is_request and tx.request then
            local func_code = tx.request.application_header.function_code
            if func_code == 2 then  -- WRITE function
                return 1
            end
        end
        
        -- Check for specific object types
        if tx.request and tx.request.objects then
            for _, obj in ipairs(tx.request.objects) do
                if obj.group == 12 and obj.variation == 1 then
                    -- Control Relay Output Block
                    return 1
                end
            end
        end
        
        return 0
    end
