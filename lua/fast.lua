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
    sid = args['sid'];
    rev = args['rev'];
    gid = args['gid'];
    msg = args['msg'];
    srcip = args['srcip'];
    dstip = args['dstip'];
    ts = args['ts'];
    class = args['class'];
    prio = args['priority'];
    proto = args['ipproto'];
    sp = args['sp'];
    dp = args['dp'];

    print (ts .. "  [**] [" .. gid .. ":" .. sid .. ":" .. rev .. "] " ..
           msg .. " [**] [Classification: " .. class .. "] [Priority: " ..
           prio .. "] {" .. proto .. "} " ..
           srcip .. ":" .. sp .. " -> " .. dstip .. ":" .. dp)

    alerts = alerts + 1;
end

function deinit (args)
    print ("Alerted " .. alerts .. " times");
end
