SSH
---

SSH transaction details are exposes to Lua scripts with the
``suricata.ssh`` library, For example::

  local ssh = require("suricata.ssh")

Setup
^^^^^

If your purpose is to create a logging script, initialize the buffer as:

::

  function init (args)
     local needs = {}
     return needs
  end

If you are going to use the script for rule matching, choose one of
the available SSH buffers listed in :ref:`lua-detection` and follow
the pattern:

::

  function init (args)
     local needs = {}
     return needs
  end

Transaction
~~~~~~~~~~~

SSH is transaction based, and the current transaction must be obtained before use::

  local tx, err = ssh.get_tx()
  if tx == err then
      print(err)
  end

All other functions are methods on the transaction table.

Transaction Methods
~~~~~~~~~~~~~~~~~~~

``server_proto()``
^^^^^^^^^^^^^^^^^^

Get the ``server_proto`` value as a string.

Example::

  local tx = ssh.get_tx()
  local proto = tx:server_proto();
  print (proto)

``client_proto()``
^^^^^^^^^^^^^^^^^^

Get the ``client_proto`` value as a string.

Example::

  local tx = ssh.get_tx()
  local proto = tx:client_proto();
  print (proto)

``server_software()``
^^^^^^^^^^^^^^^^^^^^^

Get the ``server_software`` value as a string.

Example::

  local tx = ssh.get_tx()
  local software = tx:server_software();
  print (software)

``client_software()``
^^^^^^^^^^^^^^^^^^^^^

Get the ``client_software`` value as a string.

Example::

  local tx = ssh.get_tx()
  local software = tx:client_software();
  print (software)
