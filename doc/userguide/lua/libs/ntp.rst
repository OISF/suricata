NTP
###

NTP transaction details are exposed to Lua scripts with the
``suricata.ntp`` library, for example::

  local ntp = require("suricata.ntp")

Setup
*****

If your purpose is to create a logging script, initialize the buffer as:

::

  function init (args)
     local needs = {}
     needs["protocol"] = "ntp"
     return needs
  end

Transaction
***********

NTP is transaction based, and the current transaction must be obtained
before use::

  local tx, err = ntp.get_tx()
  if tx == nil then
      print(err)
  end

All other functions are methods on the transaction table.

Transaction Methods
*******************

``version()``
=============

Get the NTP version as an integer.

``mode()``
==========

Get the NTP mode as an integer.

``stratum()``
=============

Get the NTP stratum as an integer.

``reference_id()``
==================

Get the NTP reference ID as a raw 4-byte binary string.

Example::

  local tx, err = ntp.get_tx()
  local ref_id = tx:reference_id()
  if ref_id == "\x4c\x4f\x43\x4c" then
    -- ref_id matches "LOCL"
  end

  -- If looking for a specific printable string, this is also valid
  if ref_id == "LOCL" then
    ...
  end
