Flow
----

Flows are exposed to Lua scripts with the ``suricata.flow``
library. To use it, the script must require it. For example::

    local flow = require("suricata.flow")

Following are the functions currently available for acessing Flow details.

Initialization
~~~~~~~~~~~~~~

``get``
^^^^^^^

Init the flow for use in the script. The flow is the current one the engine is
processing. ::

    f = flow.get()

Time
~~~~

``timestamps``
^^^^^^^^^^^^^^

Get timestamps of the first and the last packets from the flow, as seconds and
microseconds since `1970-01-01 00:00:00` UTC, returning 4 numbers::

    f = flow.get()
    local start_sec, last_sec, start_usec, last_usec = f:timestamps()

``timestring_legacy``
^^^^^^^^^^^^^^^^^^^^^

Get the timestamp of the first packet from the flow, as a string in the format:
`11/24/2009-18:57:25.179869`. This is the format used by `fast.log`, `http.log`
and other legacy outputs.

::

    f = flow.get()
    print f:timestring_legacy()

``timestring_iso8601``
^^^^^^^^^^^^^^^^^^^^^^

Get the timestamp of the first packet from the flow, as a string in the format:
`2015-10-06T15:16:43.136733+0000`. This is the format used by EVE outputs.

::

    f = flow.get()
    print f:timestring_iso8601()

Ports and Addresses
~~~~~~~~~~~~~~~~~~~

``tuple``
^^^^^^^^^

Using the `tuple` method, the IP version (4 or 6), src IP and dest IP (as
string), IP protocol (int), and ports (ints) are retrieved.

The protocol value comes from the IP header. See further
https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml .

::

    f = flow.get()
    ipver, srcip, dstip, proto, sp, dp = f:tuple()

App Layer Protocols
~~~~~~~~~~~~~~~~~~~

``app_layer_proto``
^^^^^^^^^^^^^^^^^^^

Get `alproto` from the flow as a string. If an `alproto` is not (yet) known, it
returns "unknown".

Returns 5 values: <alproto>, <alproto_ts>, <alproto_tc>, <alproto_orig>,
<alproto_expect>.

Example::

    f = flow.get()
    alproto, alproto_ts, alproto_tc, alproto_orig, alproto_expect = f:app_layer_proto()

`orig` and `expect` are used when changing and upgrading protocols. In an SMTP
STARTTLS case, `orig` would normally be set to "smtp" and `expect` to "tls".

Misc
~~~~

``has_alerts``
^^^^^^^^^^^^^^

Returns `true` if the flow has alerts. ::

    f = flow.get()
    alerted = f:has_alerts()

``id``
^^^^^^

Get the flow id. Note that simply printing the ``id`` will likely result in
printing a scientific notation. To avoid that, simply do::

    f = flow.get()
    id = f:id()
    id_str = string.format("%.0f", id)
    print ("Flow ID: " .. id_str .."\n")

``stats``
^^^^^^^^^

Get the packet and byte counts (for both directions), as 4 numbers, per flow.

::

    f = flow.get()
    tscnt, tsbytes, tccnt, tcbytes = f:stats()

Example
~~~~~~~

A simple ``log`` function for a script to output Flow details if the flow
triggered an alert::

    function log(args)
        local f = flow.get()
        ts = f:timestring_iso8601()
        has_alerts = f:has_alerts()
        ipver, srcip, dstip, proto, sp, dp = f:tuple()
        alproto, alproto_ts, alproto_tc, alproto_orig, alproto_expect = f:app_layer_proto()
        start_sec, start_usec, last_sec, last_usec = f:timestamps()
        id = f:id()

        if has_alerts then
            file:write ("[**] Start time " .. ts .. " [**] -> alproto " .. alproto .. " [**] " .. proto .. " [**] alerted: true\n[**] First packet: " .. start_sec .." [**] Last packet: " .. last_sec .. " [**] Flow id: " .. id .. "\n")
            file:flush()
        end
    end

For complete scripts using these and other lua functions, the Suricata-verify
can be a good resource: https://github.com/OISF/suricata-verify/tree/master/tests .
