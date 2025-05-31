-- This is a simple example script to show what you can do with lua
-- output scripts.
--
-- It prints logs similar to the ones produced by the builtin fast.log
-- output facility to stdout, hence its name.
--
-- In the init() function we tell suricata, that we want the log
-- function to be called for every packet that produces an alert (see
-- needs variable)
--
-- Then in the log() function we get various informations about this
-- packet via the "suricata.packet" and "suricata.rule" library and
-- print them to a file.
--
-- To learn more about all the API functions suricata provides for
-- your lua scripts and the lua output extension in general see:
-- http://docs.suricata.io/en/latest/output/lua-output.html

local packet = require("suricata.packet")
local rule = require("suricata.rule")
local config = require("suricata.config")

function init()
    local needs     = {}
    needs["type"]   = "packet"
    needs["filter"] = "alerts"
    return needs
end

function setup()
    filename = config.log_path() .. "/fast.log"
    file = assert(io.open(filename, "a"))
    alert_count = 0
end

function log()
    local p = packet.get()
    local s = rule.get_rule()

    local timestring = p:timestring_legacy()
    local sid = s:sid()
    local rev = s:rev()
    local gid = s:gid()
    local msg = s:msg()
    local class = s:class_description()
    local priority = s:priority()

    local ip_version, src_ip, dst_ip, protocol, src_port, dst_port = p:tuple()

    if class == nil then
        class = "unknown"
    end

    local alert = (timestring .. "  [**] [" .. gid .. ":" .. sid .. ":" .. rev .. "] " ..
           msg .. " [**] [Classification: " .. class .. "] [Priority: " ..
           priority .. "] {" .. protocol .. "} " ..
           src_ip .. ":" .. src_port .. " -> " .. dst_ip .. ":" .. dst_port)

    file:write(alert)

    alert_count = alert_count + 1;
end

function deinit()
    file:close(file)
    print ("Alerted " .. alert_count .. " times");
end
