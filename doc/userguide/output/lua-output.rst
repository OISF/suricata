.. _lua-output:

Lua Output
==========

Suricata offers the possibility to get more detailed output on specific kinds of
network traffic via pluggable lua scripts. You can write these scripts yourself and only need to
define four hook functions.

For lua output scripts suricata offers a wide range of lua functions.
They all return information on specific engine internals and aspects of the network traffic.
They are described in the following sections, grouped by the event/traffic type.
But let's start with an example explaining the four hook functions, and how to make
suricata load a lua output script.

Script structure
----------------

A lua output script needs to define 4 hook functions: init(), setup(), log(), deinit()

* init() -- registers where the script hooks into the output engine
* setup() -- does per output thread setup
* log() -- logging function
* deinit() -- clean up function

Example:

::

  local logger = require("suricata.log")

  function init (args)
      local needs = {}
      needs["protocol"] = "http"
      return needs
  end

  function setup (args)
      filename = SCLogPath() .. "/" .. name
      file = assert(io.open(filename, "a"))
      logger.info("HTTP Log Filename " .. filename)
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

      timestring = SCPacketTimeString()
      ip_version, src_ip, dst_ip, protocol, src_port, dst_port = SCFlowTuple()

      file:write (timestring .. " " .. http_host .. " [**] " .. http_uri .. " [**] " ..
             http_ua .. " [**] " .. src_ip .. ":" .. src_port .. " -> " ..
             dst_ip .. ":" .. dst_port .. "\n")
      file:flush()

      http = http + 1
  end

  function deinit (args)
      logger.info ("HTTP transactions logged: " .. http);
      file:close(file)
  end

.. _lua-output-yaml:

YAML
----

To enable the lua output, add the 'lua' output and add one or more
scripts like so:

::

  outputs:
    - lua:
        enabled: yes
        scripts-dir: /etc/suricata/lua-output/

        # By default the Lua module search paths are empty. If you plan
        # to use external modules these paths will need to be set. The
        # examples below are likely suitable for finding modules
        # installed with a package manager on a 64 bit Linux system, but
        # may need tweaking.
        #path: "/usr/share/lua/5.4/?.lua;/usr/share/lua/5.4/?/init.lua;/usr/lib64/lua/5.4/?.lua;/usr/lib64/lua/5.4/?/init.lua;./?.lua;./?/init.lua"
        #cpath: "/usr/lib64/lua/5.4/?.so;/usr/lib64/lua/5.4/loadall.so;./?.so"

        scripts:
          - tcp-data.lua
          - flow.lua

The scripts-dir option is optional. It makes Suricata load the scripts
from this directory. Otherwise scripts will be loaded from the current
workdir.

Developing lua output script
-----------------------------

You can use functions described in :ref:`Lua Functions <lua-functions>`
