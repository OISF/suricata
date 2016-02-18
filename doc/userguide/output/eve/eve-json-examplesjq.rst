Eve JSON 'jq' Examples
======================

The jq tool is very useful for quickly parsing and filtering JSON files. This page is contains various examples of how it can be used with Suricata's Eve.json.

The basics are discussed here:

* https://www.stamus-networks.com/2015/05/18/looking-at-suricata-json-events-on-command-line/

Colorize output
---------------


::


  tail -f eve.json | jq -c '.'


DNS NXDOMAIN
------------


::


  tail -f eve.json|jq -c 'select(.dns.rcode=="NXDOMAIN")'

Unique HTTP User Agents
-----------------------


::


  cat eve.json | jq -s '[.[]|.http.http_user_agent]|group_by(.)|map({key:.[0],value:(.|length)})|from_entries'

Source: https://twitter.com/mattarnao/status/601807374647750657


Data use for a host
-------------------


::


  tail -n500000 eve.json | jq -s 'map(select(.event_type=="netflow" and .dest_ip=="192.168.1.3").netflow.bytes)|add'|numfmt --to=iec
  1.3G

Note: can use a lot of memory.
Source: https://twitter.com/pkt_inspector/status/605524218722148352


Monitor part of the stats
-------------------------


::


  $ tail -f eve.json | jq -c 'select(.event_type=="stats")|.stats.decoder'

Inspect Alert Data
------------------


::


  cat eve.json | jq -r -c 'select(.event_type=="alert")|.payload'|base64 --decode

Top 10 Destination Ports
------------------------


::


  cat eve.json | jq -c 'select(.event_type=="flow")|[.proto, .dest_port]'|sort |uniq -c|sort -nr|head -n10
