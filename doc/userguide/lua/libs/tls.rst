TLS
###

.. role:: example-rule-emphasis

TLS details are exposed to Lua scripts with the
``suricata.tls`` library, for example::

  local tls = require("suricata.tls")

Setup
*****

If your purpose is to create a logging script, initialize the buffer as:

::

  function init (args)
     local needs = {}
     needs["protocol"] = "tls"
     return needs
  end

Otherwise if a detection script::

  function init (args)
    return {}
  end

API
***

Transaction
===========

TLS is transaction based, and the current transaction must be
obtained before use::

  local tx, err = tls.get_tx()
  if tx == nil then
      print(err)
  end

All other functions are methods on the transaction table.

Client Methods
==============

``get_client_version``
~~~~~~~~~~~~~~~~~~~~~~

Get the negotiated version in a TLS session as a string through ``get_client_version``.

Example:

::

  function log (args)
      t, err = tls.get_tx()
      version = t:get_client_version()
      if version ~= nil then
          -- do something
      end
  end

``get_client_cert_chain``
~~~~~~~~~~~~~~~~~~~~~~~~~

Make certificate chain available to the script through ``get_client_cert_chain``

The output is an array of certificate with each certificate being an hash
with `data` and `length` keys.

Example:

::

  -- Use debian lua-luaossl coming from https://github.com/wahern/luaossl
  local x509 = require"openssl.x509"

     chain = t:get_client_cert_chain()
     for k, v in pairs(chain) do
        -- v.length is length of data
        -- v.data is raw binary data of certificate
        print("data length is" .. v["length"] .. "\n")
        cert = x509.new(v["data"], "DER")
        print(cert:text() .. "\n")
     end

``get_client_cert_info``
~~~~~~~~~~~~~~~~~~~~~~~~

Make certificate information available to the script through ``get_client_cert_info``

Example:

::

  function log (args)
      version, subject, issuer, fingerprint = t:get_client_cert_info()
      if version ~= nil then
          -- do something
      end
  end

``get_client_cert_not_after``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Get the Unix timestamp of end of validity of certificate.

Example:

::

  function log (args)
      notafter = t:get_client_cert_not_after()
      if notafter < os.time() then
          -- expired certificate
      end
  end

``get_client_cert_not_before``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Get the Unix timestamp of beginning of validity of certificate.

Example:

::

  function log (args)
      notbefore = t:get_client_cert_not_before()
      if notbefore > os.time() then
          -- not yet valid certificate
      end
  end

``get_client_serial``
~~~~~~~~~~~~~~~~~~~~~

Get TLS certificate serial number through ``get_client_serial``.

Example:

::

  function log (args)
      serial = t:get_client_serial()
      if serial ~= nil then
          -- do something
      end
  end

``get_client_sni``
~~~~~~~~~~~~~~~~~~

Get the Server name Indication from a TLS connection.

Example:

::

  function log (args)
      asked_domain = t:get_client_sni()
      if string.find(asked_domain, "badguys") then
          -- ok connection to bad guys let's do something
      end
  end

Server Methods
==============

``get_server_cert_info``
~~~~~~~~~~~~~~~~~~~~~~~~

Make certificate information available to the script through ``get_server_cert_info``

Example:

::

  function log (args)
      version, subject, issuer, fingerprint = t:get_server_cert_info()
      if version ~= nil then
          -- do something
      end
  end

``get_server_cert_chain``
~~~~~~~~~~~~~~~~~~~~~~~~~

Make certificate chain available to the script through ``get_server_cert_chain``

The output is an array of certificate with each certificate being an hash
with `data` and `length` keys.

Example:

::

  -- Use debian lua-luaossl coming from https://github.com/wahern/luaossl
  local x509 = require"openssl.x509"

     chain = t:get_server_cert_chain()
     for k, v in pairs(chain) do
        -- v.length is length of data
        -- v.data is raw binary data of certificate
        print("data length is" .. v["length"] .. "\n")
        cert = x509.new(v["data"], "DER")
        print(cert:text() .. "\n")
     end


``get_server_cert_not_after``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Get the Unix timestamp of end of validity of certificate.

Example:

::

  function log (args)
      notafter = t:get_server_cert_not_after()
      if notafter < os.time() then
          -- expired certificate
      end
  end

``get_server_cert_not_before``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Get the Unix timestamp of beginning of validity of certificate.

Example:

::

  function log (args)
      notbefore = t:get_server_cert_not_before()
      if notbefore > os.time() then
          -- not yet valid certificate
      end
  end

``get_server_serial``
~~~~~~~~~~~~~~~~~~~~~

Get TLS certificate serial number through ``get_server_serial``.

Example:

::

  function log (args)
      serial = t:get_server_serial()
      if serial ~= nil then
          -- do something
      end
  end

