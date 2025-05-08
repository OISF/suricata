JA3
---

JA3 details are exposed to Lua scripts with the
``suricata.ja3`` library. For example::

  local ja3 = require("suricata.ja3")

If you want to use ja3, you can either set suricata.yaml option
``app-layer.protocols.tls.ja3-fingerprints`` to true,
or specify it in the ``init`` function of your lua script
by calling ``ja3.enable_ja3()``::

  function init (args)
    ja3.enable_ja3()
    return {}
  end

``ja3.enable_ja3()`` will not enable ja3 if they are explicitly
disabled, so you should add ``requires: feature ja3;``
(see :ref:`keyword_requires`) to your rule.

For use in rule matching, the rule should use need ``ja3`` or
``ja3s`` in your init script::

  function init (args)
    ja3.enable_ja3()
    local needs = {}
    needs["ja3s"] = true
    return needs
  end

Transaction
~~~~~~~~~~~

JA3 is transaction based, and the current transaction must be obtained before use::

  local tx, err = ja3.get_tx()
  if tx == err then
      print(err)
  end

All other functions are methods on the transaction (either a QUIC or a TLS one).

Transaction Methods
~~~~~~~~~~~~~~~~~~~

``ja3_get_hash()``
^^^^^^^^^^^^^^^^^^

Get the ja3 value as a hash.

Example::

  local tx = ja3.get_tx()
  local h = tx:ja3_get_hash();
  print (h)

``ja3_get_string()``
^^^^^^^^^^^^^^^^^^^^

Get the ja3 value as a string.

Example::

  local tx = ja3.get_tx()
  local s = tx:ja3_get_string();
  print (s)

``ja3s_get_hash()``
^^^^^^^^^^^^^^^^^^^

Get the ja3s value as a hash.

Example::

  local tx = ja3.get_tx()
  local h = tx:ja3s_get_hash();
  print (h)

``ja3s_get_string()``
^^^^^^^^^^^^^^^^^^^^^

Get the ja3s value as a string.

Example::

  local tx = ja3.get_tx()
  local s = tx:ja3s_get_string();
  print (s)