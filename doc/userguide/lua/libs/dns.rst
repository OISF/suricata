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

Functions
~~~~~~~~~

``answers()``
^^^^^^^^^^^^^

Get the ``answers`` response section as a table of tables.

Example::

  dns_answers = dns.answers();
  if dns_answers ~= nil then
      for n, t in pairs(dns_answers) do
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

  dns_auth = dns.authorities();
  if dns_auth ~= nil then
      for n, t in pairs(dns_auth) do
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

  dns_query = dns.queries();
  if dns_query ~= nil then
      for n, t in pairs(dns_query) do
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

  local rcode = dns.rcode();
  print (rcode)

``rcode_string()``
^^^^^^^^^^^^^^^^^^

Get the ``rcode`` value as a string.

Example::

  local rcode_string = dns.rcode_string();
  print (rcode_string)

``recursion_desired()``
^^^^^^^^^^^^^^^^^^^^^^^

Return the value of the recursion desired (RD) flag as a boolean.

Example::

  if dns.recursion_desired() == true then
      print ("RECURSION DESIRED")
  end

``rrname()``
^^^^^^^^^^^^

Return the resource name from the first query object.

Example::

  local rrname = dns.rrname()
  print(rrname)

``txid()``
^^^^^^^^^^

Return the DNS transaction ID found in the DNS message.

Example::

  local txid = dns.txid()
  print(txid)
