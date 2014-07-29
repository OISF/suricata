-- simple fast-log to stdout lua module

function init (args)
    local needs = {}
    needs["type"] = "packet"
    needs["filter"] = "alerts"
    return needs
end

function setup (args)
    alerts = 0
end

function log(args)
    ts = SCPacketTimeString()
    sid, rev, gid = SCRuleIds()
    ipver, srcip, dstip, proto, sp, dp = SCPacketTuple()
    msg = SCRuleMsg()
    class, prio = SCRuleClass()
    if class == nil then
        class = "unknown"
    end

    print (ts .. "  [**] [" .. gid .. ":" .. sid .. ":" .. rev .. "] " ..
           msg .. " [**] [Classification: " .. class .. "] [Priority: " ..
           prio .. "] {" .. proto .. "} " ..
           srcip .. ":" .. sp .. " -> " .. dstip .. ":" .. dp)

    alerts = alerts + 1;
end

function deinit (args)
    print ("Alerted " .. alerts .. " times");
end
