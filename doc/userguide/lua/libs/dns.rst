DNS
---

DNS transaction details are exposes to Lua scripts with the
``suricata.dns`` library, For example::

  local dns = require("suricata.dns")

Setup
^^^^^

If your purpose is to create a logging script, initialize the buffer as:

::

  function init (args)
     local needs = {}
     needs["protocol"] = "dns"
     return needs
  end

If you are going to use the script for rule matching, choose one of
the available DNS buffers listed in :ref:`lua-detection` and follow
the pattern:

::

  function init (args)
     local needs = {}
     needs["dns.rrname"] = tostring(true)
     return needs
  end

Transaction
~~~~~~~~~~~

DNS is transaction based, and the current transaction must be obtained before use::

  local tx, err = dns.get_tx()
  if tx == err then
      print(err)
  end

All other functions are methods on the transaction table.

Transaction Methods
~~~~~~~~~~~~~~~~~~~

``answers()``
^^^^^^^^^^^^^

Get the ``answers`` response section as a table of tables.

Example::

  local tx = dns.get_tx()
  local answers = tx:answers()
  if answers ~= nil then
      for n, t in pairs(answers) do
          rrname = t["rrname"]
          rrtype = t["type"]
          ttl = t["ttl"]

          print ("ANSWER: " .. ts .. " " .. rrname .. " [**] " .. rrtype .. " [**] " ..
                 ttl .. " [**] " .. srcip .. ":" .. sp .. " -> " ..
                 dstip .. ":" .. dp)
      end
  end

``authorities()``
^^^^^^^^^^^^^^^^^

Get the ``authorities`` response section as a table of tables.

Example::

  local tx = dns.get_tx()
  local authorities = tx:authorities();
  if authorities ~= nil then
      for n, t in pairs(authorities) do
          rrname = t["rrname"]
          rrtype = t["type"]
          ttl = t["ttl"]
           print ("AUTHORITY: " .. ts .. " " .. rrname .. " [**] " .. rrtype .. " [**] " ..
                 ttl .. " [**] " .. srcip .. ":" .. sp .. " -> " ..
                 dstip .. ":" .. dp)
      end
  end

``queries()``
^^^^^^^^^^^^^

Get the ``queries`` request or response section as a table of tables.

Example::

  local tx = dns.get_tx()
  local queries = tx:queries();
  if queries ~= nil then
      for n, t in pairs(queries) do
          rrname = t["rrname"]
          rrtype = t["type"]

          print ("QUERY: " .. ts .. " " .. rrname .. " [**] " .. rrtype .. " [**] " ..
                 "TODO" .. " [**] " .. srcip .. ":" .. sp .. " -> " ..
                 dstip .. ":" .. dp)
      end
  end

``rcode()``
^^^^^^^^^^^

Get the ``rcode`` value as an integer.

Example::

  local tx = dns.get_tx()
  local rcode = tx:rcode()
  print (rcode)

``rcode_string()``
^^^^^^^^^^^^^^^^^^

Get the ``rcode`` value as a string.

Example::

  local tx = dns.get_tx()
  local rcode_string = tx:rcode_string();
  print (rcode_string)

``recursion_desired()``
^^^^^^^^^^^^^^^^^^^^^^^

Return the value of the recursion desired (RD) flag as a boolean.

Example::

  local tx = dns.get_tx()
  if tx:recursion_desired() == true then
      print ("RECURSION DESIRED")
  end

``rrname()``
^^^^^^^^^^^^

Return the resource name from the first query object.

Example::

  local tx = dns.get_tx()
  local rrname = tx:rrname()
  print(rrname)

``txid()``
^^^^^^^^^^

Return the DNS transaction ID found in the DNS message.

Example::

  local tx = dns.get_tx()
  local txid = tx:txid()
  print(txid)
