Packet
------

Packets are exposed to Lua scripts with ``suricata.packet``
library. For example::

    local packet = require("suricata.packet")

Initialization
~~~~~~~~~~~~~~

``get``
^^^^^^^

Init the packet for use in the script. The packet is the current packet the engine is processing.

::

    p = packet.get()


Time
~~~~

``timestamp``
^^^^^^^^^^^^^

Get packet timestamp as 2 numbers: seconds & microseconds elapsed since
1970-01-01 00:00:00 UTC.

::

    p = packet.get()
    local sec, usec = p:timestamp()


``timestring_legacy``
^^^^^^^^^^^^^^^^^^^^^

Get packet timestamp as a string in the format: `11/24/2009-18:57:25.179869`.
This is the format used by `fast.log`, `http.log` and other legacy outputs.

::

    p = packet.get()
    print p:timestring_legacy()


``timestring_iso8601``
^^^^^^^^^^^^^^^^^^^^^^

Get packet timestamp as a string in the format: `2015-10-06T15:16:43.137833+0000`.
This is the format used by `eve`.

::

    p = packet.get()
    print p:timestring_iso8601()


Ports and Addresses
~~~~~~~~~~~~~~~~~~~

``tuple``
^^^^^^^^^

Using the `tuple` method the IP version (4 or 6), src IP and dest IP (as string), IP protocol (int) and ports (ints) are retrieved.

The protocol value comes from the IP header, see further https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

::

    p = packet.get()
    ipver, srcip, dstip, proto, sp, dp = p:tuple()


If the protocol is ICMPv4 or ICMPv6, so when `proto == 1` or `proto == 58`, then the final two results are `icmp type` and `icmp code`.

::

    p = packet.get()
    ipver, srcip, dstip, proto, itype, icode = p:tuple()
    if ipver == 6 and proto == 1 then
        -- weird, ICMPv4 on IPv6
        return 1
    end


``sp``
^^^^^^

Get the packets TCP, UDP or SCTP source port as an int. Returns `nil` for other protocols.

::

    p = packet.get()
    source_port = p:sp()
    if source_port == 31337 then
        return 1
    end


``dp``
^^^^^^

Get the packets TCP, UDP or SCTP destination port as an int. Returns `nil` for other protocols.

::

    p = packet.get()
    dest_port = p:dp()
    -- not port 443
    if dest_port ~= 443 then
        return 1
    end


Data
~~~~

``payload``
^^^^^^^^^^^

Packet payload.

::

    payload = p:payload()


``packet``
^^^^^^^^^^

Entire packet, including headers for protocols like TCP, Ethernet, VLAN, etc.

::

    raw_packet = p:packet()


Misc
~~~~

``pcap_cnt``
^^^^^^^^^^^^

The packet number when reading from a pcap file.

::

    p = packet.get()
    print p:pcap_cnt()


Example
~~~~~~~

Example `match` function that takes a packet, inspect the payload line by line and checks if it finds the HTTP request line.
If it is found, issue a notice log with packet details.

::

    local logger = require("suricata.log")

    function match (args)
        p = packet.get()
        payload = p:payload()
        ts = p:timestring()

        for line in payload:gmatch("([^\r\n]*)[\r\n]+") do
            if line == "GET /index.html HTTP/1.0" then
                ipver, srcip, dstip, proto, sp, dp = p:tuple()
                logger.notice(string.format("%s %s->%s %d->%d (pcap_cnt:%d) match! %s", ts, srcip, dstip, sp, dp, p:pcap_cnt(), line));
                return 1
            end
        end

        return 0
    end
