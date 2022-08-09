-- This is a simple example script to show what you can do with lua output scripts.
-- It prints logs similar to the ones produced by the builtin fast.log output
-- facility to stdout, hence its name.

-- In the init() function we tell suricata, that we want the log function to be
-- called for every packet that produces an alert (see needs variable)

-- Then in the log() function we get various informations about this packet via
-- SCRuleMsg() and all the other API functions and print them to stdout with print()

-- To learn more about all the API functions suricata provides for your lua scripts
-- and the lua output extension in general see:
-- http://suricata.readthedocs.io/en/latest/output/lua-output.html

function init()
    local needs     = {}
    needs["type"]   = "packet"
    needs["filter"] = "alerts"
    return needs
end

function setup()
    alert_count = 0
end

function log()
    timestring      = SCPacketTimeString()
    sid, rev, gid   = SCRuleIds()
    msg             = SCRuleMsg()
    class, priority = SCRuleClass()

    ip_version, src_ip, dst_ip, protocol, src_port, dst_port = SCPacketTuple()

    if class == nil then
        class = "unknown"
    end

    print (timestring .. "  [**] [" .. gid .. ":" .. sid .. ":" .. rev .. "] " ..
           msg .. " [**] [Classification: " .. class .. "] [Priority: " ..
           priority .. "] {" .. protocol .. "} " ..
           src_ip .. ":" .. src_port .. " -> " .. dst_ip .. ":" .. dst_port)

    alert_count = alert_count + 1;
end

function deinit()
    print ("Alerted " .. alert_count .. " times");
end
