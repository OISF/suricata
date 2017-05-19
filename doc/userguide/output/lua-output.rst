Lua Output
==========

Lua scripts can be used to generate output from Suricata.

Script structure
----------------

A script defines 4 functions: init, setup, log, deinit

* init -- registers where the script hooks into the output engine
* setup -- does per output thread setup
* log -- logging function
* deinit -- clean up function

Example:

::

  function init (args)
      local needs = {}
      needs["protocol"] = "http"
      return needs
  end

  function setup (args)
      filename = SCLogPath() .. "/" .. name
      file = assert(io.open(filename, "a"))
      SCLogInfo("HTTP Log Filename " .. filename)
      http = 0
  end

  function log(args)
      http_uri = HttpGetRequestUriRaw()
      if http_uri == nil then
          http_uri = "<unknown>"
      end
      http_uri = string.gsub(http_uri, "%c", ".")

      http_host = HttpGetRequestHost()
      if http_host == nil then
          http_host = "<hostname unknown>"
      end
      http_host = string.gsub(http_host, "%c", ".")

      http_ua = HttpGetRequestHeader("User-Agent")
      if http_ua == nil then
          http_ua = "<useragent unknown>"
      end
      http_ua = string.gsub(http_ua, "%g", ".")

      ts = SCPacketTimeString()
      ipver, srcip, dstip, proto, sp, dp = SCFlowTuple()

      file:write (ts .. " " .. http_host .. " [**] " .. http_uri .. " [**] " ..
             http_ua .. " [**] " .. srcip .. ":" .. sp .. " -> " ..
             dstip .. ":" .. dp .. "\n")
      file:flush()

      http = http + 1
  end

  function deinit (args)
      SCLogInfo ("HTTP transactions logged: " .. http);
      file:close(file)
  end

YAML
----

To enable the lua output, add the 'lua' output and add one or more
scripts like so:

::

  outputs:
    - lua:
        enabled: yes
        scripts-dir: /etc/suricata/lua-output/
        scripts:
          - tcp-data.lua
          - flow.lua

The scripts-dir option is optional. It makes Suricata load the scripts
from this directory. Otherwise scripts will be loaded from the current
workdir.

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

Add SCPacketTimeString to get the packets time string in the format:
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

Get alprotos as string from the flow. If a alproto is not (yet) known, it
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

Init with:

::

  function init (args)
      local needs = {}
      needs["protocol"] = "http"
      return needs
  end

HttpGetRequestBody and HttpGetResponseBody.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Make normalized body data available to the script through
HttpGetRequestBody and HttpGetResponseBody.

There no guarantees that all of the body will be availble.

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

Initialize with:

::

  function init (args)
      local needs = {}
      needs["protocol"] = "tls"
      return needs
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


  fileid, txid, name, size, magic, md5 = SCFileInfo()

returns fileid (number), txid (number), name (string), size (number),
magic (string), md5 in hex (string)

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
      data = SCStreamingBuffer()
      hex_dump(data)
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
