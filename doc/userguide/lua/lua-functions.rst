.. _lua-functions:

Lua functions
=============

Differences between `output` and `detect`:
------------------------------------------

Currently, the ``needs`` key initialization varies, depending on what is the goal of the script: output or detection.
The Lua script for the ``luaxform`` transform **does not use ``needs``**.

If the script is for detection, the ``needs`` initialization should be as seen in the example below (see :ref:`lua-detection` for a complete example of a detection script):

::

  function init (args)
      local needs = {}
      needs["packet"] = tostring(true)
      return needs
  end

For output logs, follow the pattern below. (The complete script structure can be seen at :ref:`lua-output`:)

::

  function init (args)
      local needs = {}
      needs["protocol"] = "http"
      return needs
  end


Do notice that the functions and protocols available for ``log`` and ``match`` may also vary. DNP3, for instance, is not
available for logging.

packet
------

Initialize with:

::

  function init (args)
      local needs = {}
      needs["type"] = "packet"
      return needs
  end

SCPacketTimestamp
~~~~~~~~~~~~~~~~~

Get packets timestamp as 2 numbers: seconds & microseconds elapsed since
1970-01-01 00:00:00 UTC.

::

  function log(args)
      local sec, usec = SCPacketTimestamp()
  end

SCPacketTimeString
~~~~~~~~~~~~~~~~~~

Use ``SCPacketTimeString`` to get the packet's time string in the format:
11/24/2009-18:57:25.179869

::

  function log(args)
      ts = SCPacketTimeString()

SCPacketTuple
~~~~~~~~~~~~~

::

  ipver, srcip, dstip, proto, sp, dp = SCPacketTuple()

SCPacketPayload
~~~~~~~~~~~~~~~

::

  p = SCPacketPayload()

flow
----

::

  function init (args)
      local needs = {}
      needs["type"] = "flow"
      return needs
  end

SCFlowTimestamps
~~~~~~~~~~~~~~~~

Get timestamps (seconds and microseconds) of the first and the last packet from
the flow.

::

  startts, lastts = SCFlowTimestamps()
  startts_s, lastts_s, startts_us, lastts_us = SCFlowTimestamps()

SCFlowTimeString
~~~~~~~~~~~~~~~~

::

  startts = SCFlowTimeString()

SCFlowTuple
~~~~~~~~~~~

::

  ipver, srcip, dstip, proto, sp, dp = SCFlowTuple()

SCFlowAppLayerProto
~~~~~~~~~~~~~~~~~~~

Get alproto as a string from the flow. If a alproto is not (yet) known, it
returns "unknown".

Example:

::

  function log(args)
      alproto = SCFlowAppLayerProto()
      if alproto ~= nil then
          print (alproto)
      end
  end

Returns 5 values: <alproto> <alproto_ts> <alproto_tc> <alproto_orig> <alproto_expect>

Orig and expect are used when changing and upgrading protocols. In a SMTP STARTTLS
case, orig would normally be set to "smtp" and expect to "tls".


SCFlowHasAlerts
~~~~~~~~~~~~~~~

Returns true if flow has alerts.

Example:

::

  function log(args)
      has_alerts = SCFlowHasAlerts()
      if has_alerts then
          -- do something
      end
  end

SCFlowStats
~~~~~~~~~~~

Gets the packet and byte counts per flow.

::

  tscnt, tsbytes, tccnt, tcbytes = SCFlowStats()

SCFlowId
~~~~~~~~

Gets the flow id.

::

    id = SCFlowId()

Note that simply printing 'id' will likely result in printing a scientific
notation. To avoid that, simply do:

::

    id = SCFlowId()
    idstr = string.format("%.0f",id)
    print ("Flow ID: " .. idstr .. "\n")


http
----

For output, init with:

::

  function init (args)
      local needs = {}
      needs["protocol"] = "http"
      return needs
  end

For detection, use the specific buffer (cf :ref:`lua-detection` for a complete list), as with:

::

  function init (args)
      local needs = {}
      needs["http.uri"] = tostring(true)
      return needs
  end

HttpGetRequestBody and HttpGetResponseBody.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Make normalized body data available to the script through
HttpGetRequestBody and HttpGetResponseBody.

There no guarantees that all of the body will be available.

Example:

::

  function log(args)
      a, o, e = HttpGetResponseBody();
      --print("offset " .. o .. " end " .. e)
      for n, v in ipairs(a) do
          print(v)
      end
  end

HttpGetRequestHost
~~~~~~~~~~~~~~~~~~

Get the host from libhtp's tx->request_hostname, which can either be
the host portion of the url or the host portion of the Host header.

Example:

::

  http_host = HttpGetRequestHost()
  if http_host == nil then
      http_host = "<hostname unknown>"
  end

HttpGetRequestHeader
~~~~~~~~~~~~~~~~~~~~

::

  http_ua = HttpGetRequestHeader("User-Agent")
  if http_ua == nil then
      http_ua = "<useragent unknown>"
  end

HttpGetResponseHeader
~~~~~~~~~~~~~~~~~~~~~

::

  server = HttpGetResponseHeader("Server");
  print ("Server: " .. server);

HttpGetRequestLine
~~~~~~~~~~~~~~~~~~

::

  rl = HttpGetRequestLine();
  print ("Request Line: " .. rl);

HttpGetResponseLine
~~~~~~~~~~~~~~~~~~~

::

  rsl = HttpGetResponseLine();
  print ("Response Line: " .. rsl);

HttpGetRawRequestHeaders
~~~~~~~~~~~~~~~~~~~~~~~~

::

  rh = HttpGetRawRequestHeaders();
  print ("Raw Request Headers: " .. rh);

HttpGetRawResponseHeaders
~~~~~~~~~~~~~~~~~~~~~~~~~

::

  rh = HttpGetRawResponseHeaders();
  print ("Raw Response Headers: " .. rh);

HttpGetRequestUriRaw
~~~~~~~~~~~~~~~~~~~~

::

  http_uri = HttpGetRequestUriRaw()
  if http_uri == nil then
      http_uri = "<unknown>"
  end

HttpGetRequestUriNormalized
~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

  http_uri = HttpGetRequestUriNormalized()
  if http_uri == nil then
      http_uri = "<unknown>"
  end

HttpGetRequestHeaders
~~~~~~~~~~~~~~~~~~~~~

::

  a = HttpGetRequestHeaders();
  for n, v in pairs(a) do
      print(n,v)
  end

HttpGetResponseHeaders
~~~~~~~~~~~~~~~~~~~~~~

::

  a = HttpGetResponseHeaders();
  for n, v in pairs(a) do
      print(n,v)
  end

DNS
---

If your purpose is to create a logging script, initialize the buffer as:

::

  function init (args)
     local needs = {}
     needs["protocol"] = "dns"
     return needs
  end

If you are going to use the script for rule matching, choose one of the available DNS buffers listed in
:ref:`lua-detection` and follow the pattern:

::

  function init (args)
     local needs = {}
     needs["dns.rrname"] = tostring(true)
     return needs
  end

DnsGetQueries
~~~~~~~~~~~~~

::

  dns_query = DnsGetQueries();
  if dns_query ~= nil then
      for n, t in pairs(dns_query) do
          rrname = t["rrname"]
          rrtype = t["type"]

          print ("QUERY: " .. ts .. " " .. rrname .. " [**] " .. rrtype .. " [**] " ..
                 "TODO" .. " [**] " .. srcip .. ":" .. sp .. " -> " ..
                 dstip .. ":" .. dp)
      end
  end

returns a table of tables

DnsGetAnswers
~~~~~~~~~~~~~

::

  dns_answers = DnsGetAnswers();
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

returns a table of tables

DnsGetAuthorities
~~~~~~~~~~~~~~~~~

::

  dns_auth = DnsGetAuthorities();
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

returns a table of tables

DnsGetRcode
~~~~~~~~~~~

::

  rcode = DnsGetRcode();
  if rcode == nil then
      return 0
  end
  print (rcode)

returns a lua string with the error message, or nil

DnsGetRecursionDesired
~~~~~~~~~~~~~~~~~~~~~~

::

  if DnsGetRecursionDesired() == true then
      print ("RECURSION DESIRED")
  end

returns a bool

TLS
---

For log output, initialize with:

::

  function init (args)
      local needs = {}
      needs["protocol"] = "tls"
      return needs
  end

For detection, initialization is as follows:

::

  function init (args)
      local needs = {}
      needs["tls"] = tostring(true)
      return needs
  end

TlsGetVersion
~~~~~~~~~~~~~

Get the negotiated version in a TLS session as a string through TlsGetVersion.

Example:

::

  function log (args)
      version = TlsGetVersion()
      if version then
          -- do something
      end
  end

TlsGetCertInfo
~~~~~~~~~~~~~~

Make certificate information available to the script through TlsGetCertInfo.

Example:

::

  function log (args)
      version, subject, issuer, fingerprint = TlsGetCertInfo()
      if version == nil then
          return 0
      end
  end

TlsGetCertChain
~~~~~~~~~~~~~~~

Make certificate chain available to the script through TlsGetCertChain.

The output is an array of certificate with each certificate being an hash
with `data` and `length` keys.

Example:

::

  -- Use debian lua-luaossl coming from https://github.com/wahern/luaossl
  local x509 = require"openssl.x509"

     chain = TlsGetCertChain()
     for k, v in pairs(chain) do
        -- v.length is length of data
        -- v.data is raw binary data of certificate
        cert = x509.new(v["data"], "DER")
        print(cert:text() .. "\n")
     end


TlsGetCertNotAfter
~~~~~~~~~~~~~~~~~~

Get the Unix timestamp of end of validity of certificate.

Example:

::

  function log (args)
      notafter = TlsGetCertNotAfter()
      if notafter < os.time() then
          -- expired certificate
      end
  end

TlsGetCertNotBefore
~~~~~~~~~~~~~~~~~~~

Get the Unix timestamp of beginning of validity of certificate.

Example:

::

  function log (args)
      notbefore = TlsGetCertNotBefore()
      if notbefore > os.time() then
          -- not yet valid certificate
      end
  end

TlsGetCertSerial
~~~~~~~~~~~~~~~~

Get TLS certificate serial number through TlsGetCertSerial.

Example:

::

  function log (args)
      serial = TlsGetCertSerial()
      if serial then
          -- do something
      end
  end

TlsGetSNI
~~~~~~~~~

Get the Server name Indication from a TLS connection.

Example:

::

  function log (args)
      asked_domain = TlsGetSNI()
      if string.find(asked_domain, "badguys") then
          -- ok connection to bad guys let's do something
      end
  end


JA3
---

JA3 must be enabled in the Suricata config file (set 'app-layer.protocols.tls.ja3-fingerprints' to 'yes').

For log output, initialize with:

::

  function init (args)
      local needs = {}
      needs["protocol"] = "tls"
      return needs
  end

For detection, initialization is as follows:

::

  function init (args)
      local needs = {}
      needs["tls"] = tostring(true)
      return needs
  end

Ja3GetHash
~~~~~~~~~~

Get the JA3 hash (md5sum of JA3 string) through Ja3GetHash.

Example:

::

  function log (args)
      hash = Ja3GetHash()
      if hash == nil then
          return
      end
  end

Ja3GetString
~~~~~~~~~~~~

Get the JA3 string through Ja3GetString.

Example:

::

  function log (args)
      str = Ja3GetString()
      if str == nil then
          return
      end
  end

Ja3SGetHash
~~~~~~~~~~~

Get the JA3S hash (md5sum of JA3S string) through JA3SGetHash.

Examples:

::

  function log (args)
      hash = Ja3SGetHash()
      if hash == nil then
          return
      end
  end

Or, for detection:

::

  function match (args)
      hash = Ja3SGetHash()
      if hash == nil then
        return 0
      end

      // matching code

      return 0
  end

JA3SGetString
~~~~~~~~~~~~~

Get the JA3S string through Ja3SGetString.

Examples:

::

  function log (args)
      str = Ja3SGetString()
      if str == nil then
          return
      end
  end

Or, for detection:

::

  function match (args)
    str = Ja3SGetString()
    if str == nil then
      return 0
    end

    // matching code

    return 0
  end

SSH
---

Initialize with:

::

  function init (args)
      local needs = {}
      needs["protocol"] = "ssh"
      return needs
  end

SshGetServerProtoVersion
~~~~~~~~~~~~~~~~~~~~~~~~

Get SSH protocol version used by the server through SshGetServerProtoVersion.

Example:

::

  function log (args)
      version = SshGetServerProtoVersion()
      if version == nil then
          return 0
      end
  end

SshGetServerSoftwareVersion
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Get SSH software used by the server through SshGetServerSoftwareVersion.

Example:

::

  function log (args)
      software = SshGetServerSoftwareVersion()
      if software == nil then
          return 0
      end
  end

SshGetClientProtoVersion
~~~~~~~~~~~~~~~~~~~~~~~~

Get SSH protocol version used by the client through SshGetClientProtoVersion.

Example:

::

  function log (args)
      version = SshGetClientProtoVersion()
      if version == nil then
          return 0
      end
  end

SshGetClientSoftwareVersion
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Get SSH software used by the client through SshGetClientSoftwareVersion.

Example:

::

  function log (args)
      software = SshGetClientSoftwareVersion()
      if software == nil then
          return 0
      end
  end


HasshGet
~~~~~~~~

Get MD5 of hassh algorithms used by the client through HasshGet.

Example:

::

  function log (args)
      hassh = HasshGet()
      if hassh == nil then
          return 0
      end
  end

HasshGetString
~~~~~~~~~~~~~~

Get hassh algorithms used by the client through HasshGetString.

Example:

::

  function log (args)
      hassh_string = HasshGetString()
      if hassh == nil then
          return 0
      end
  end

HasshServerGet
~~~~~~~~~~~~~~

Get MD5 of hassh algorithms used by the server through HasshServerGet.

Example:

::

  function log (args)
      hassh_string = HasshServerGet()
      if hassh == nil then
          return 0
      end
  end

HasshServerGetString
~~~~~~~~~~~~~~~~~~~~

Get hassh algorithms used by the server through HasshServerGetString.

Example:

::

  function log (args)
      hassh_string = HasshServerGetString()
      if hassh == nil then
          return 0
      end
  end


Files
-----

To use the file logging API, the script's init() function needs to look like:

::

  function init (args)
      local needs = {}
      needs['type'] = 'file'
      return needs
  end

SCFileInfo
~~~~~~~~~~

::


  fileid, txid, name, size, magic, md5, sha1, sha256 = SCFileInfo()

returns fileid (number), txid (number), name (string), size (number),
magic (string), md5 in hex (string), sha1 (string), sha256 (string)

SCFileState
~~~~~~~~~~~

::

  state, stored = SCFileState()

returns state (string), stored (bool)

Alerts
------

Alerts are a subset of the 'packet' logger:

::

  function init (args)
      local needs = {}
      needs["type"] = "packet"
      needs["filter"] = "alerts"
      return needs
  end

SCRuleIds
~~~~~~~~~

::

  sid, rev, gid = SCRuleIds()

SCRuleAction
~~~~~~~~~~~~

::

  action = SCRuleAction()

returns one of 'pass', 'reject', 'drop' or 'alert'

SCRuleMsg
~~~~~~~~~

::

  msg = SCRuleMsg()

SCRuleClass
~~~~~~~~~~~

::


  class, prio = SCRuleClass()

Streaming Data
--------------

Streaming data can currently log out reassembled TCP data and
normalized HTTP data. The script will be invoked for each consecutive
data chunk.

In case of TCP reassembled data, all possible overlaps are removed
according to the host OS settings.

::

  function init (args)
      local needs = {}
      needs["type"] = "streaming"
      needs["filter"] = "tcp"
      return needs
  end

In case of HTTP body data, the bodies are unzipped and dechunked if applicable.

::

  function init (args)
      local needs = {}
      needs["type"] = "streaming"
      needs["protocol"] = "http"
      return needs
  end

SCStreamingBuffer
~~~~~~~~~~~~~~~~~

::

  function log(args)
      -- sb_ts and sb_tc are bools indicating the direction of the data
      data, sb_open, sb_close, sb_ts, sb_tc = SCStreamingBuffer()
      if sb_ts then
        print("->")
      else
        print("<-")
      end
      hex_dump(data)
  end

Flow variables
--------------

It is possible to access, define and modify Flow variables from Lua. To do so,
you must use the functions described in this section and declare the counter in
init function:

::

 function init(args)
     local needs = {}
     needs["tls"] tostring(true)
     needs["flowint"] = {"tls-cnt"}
     return needs
 end

Here we define a `tls-cnt` Flowint that can now be used in output or in a
signature via dedicated functions. The access to the Flow variable is done by
index so in our case we need to use 0.

::

 function match(args)
     a = SCFlowintGet(0);
     if a then
         SCFlowintSet(0, a + 1)
     else
         SCFlowintSet(0, 1)
     end

SCFlowintGet
~~~~~~~~~~~~

Get the Flowint at index given by the parameter.

SCFlowintSet
~~~~~~~~~~~~

Set the Flowint at index given by the first parameter. The second parameter is the value.

SCFlowintIncr
~~~~~~~~~~~~~

Increment Flowint at index given by the first parameter.

SCFlowintDecr
~~~~~~~~~~~~~

Decrement Flowint at index given by the first parameter.

SCFlowvarGet
~~~~~~~~~~~~

Get the Flowvar at index given by the parameter.

SCFlowvarSet
~~~~~~~~~~~~

Set a Flowvar. First parameter is the index, second is the data
and third is the length of data.

You can use it to set string

::

 function init (args)
     local needs = {}
     needs["http.request_headers"] = tostring(true)
     needs["flowvar"] = {"cnt"}
     return needs
 end

 function match(args)
     a = SCFlowvarGet(0);
     if a then
         a = tostring(tonumber(a)+1)
         SCFlowvarSet(0, a, #a)
     else
         a = tostring(1)
         SCFlowvarSet(0, a, #a)
     end

Misc
----

SCThreadInfo
~~~~~~~~~~~~

::

  tid, tname, tgroup = SCThreadInfo()

It gives: tid (integer), tname (string), tgroup (string)

SCLogError, SCLogWarning, SCLogNotice, SCLogInfo, SCLogDebug
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Print a message. It will go into the outputs defined in the
yaml. Whether it will be printed depends on the log level.

Example:

::

  SCLogError("some error message")

SCLogPath
~~~~~~~~~

Expose the log path.

::


  name = "fast_lua.log"
  function setup (args)
      filename = SCLogPath() .. "/" .. name
      file = assert(io.open(filename, "a"))
  end

SCByteVarGet
~~~~~~~~~~~~

Get the ByteVar at index given by the parameter. These variables are defined by
`byte_extract` or `byte_math` in Suricata rules. Only callable from match scripts.

::

 function init(args)
     local needs = {}
     needs["bytevar"] = {"var1", "var2"}
     return needs
 end

Here we define a register that we will be using variables `var1` and `var2`.
The access to the Byte variables is done by index.

::

 function match(args)
     var1 = SCByteVarGet(0)
     var2 = SCByteVarGet(1)
