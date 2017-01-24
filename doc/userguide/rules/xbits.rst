Xbits
=====

Set, unset, toggle and check for bits stored per host or ip_pair.

Syntax::

    xbits:noalert;
    xbits:<set|unset|isset|toggle>,<name>,track <ip_src|ip_dst|ip_pair>;
    xbits:<set|unset|isset|toggle>,<name>,track <ip_src|ip_dst|ip_pair> \
        [,expire <seconds>];
    xbits:<set|unset|isset|toggle>,<name>,track <ip_src|ip_dst|ip_pair> \
        [,expire <seconds>];

YAML settings
-------------

Bits that are stored per host are stored in the Host table.

Bits that are stored per IP pair are stored in the IPPair table.

Threading
---------

Due to subtle timing issues between threads the order of sets and checks
can be slightly unpredictible.

Unix Socket
-----------

Hostbits can be added, removed and listed through the unix socket.

Add::

    suricatasc -c "add-hostbit <ip> <bit name> <expire in seconds>"
    suricatasc -c "add-hostbit 1.2.3.4 blacklist 3600"

If an hostbit is added for an existing hostbit, it's expiry timer is updated.

Remove::

    suricatasc -c "remove-hostbit <ip> <bit name>"
    suricatasc -c "remove-hostbit 1.2.3.4 blacklist"

List::

    suricatasc -c "list-hostbit <ip>"
    suricatasc -c "list-hostbit 1.2.3.4"

This results in::

    {
        "message":
        {
           "count": 1,
           "hostbits":
                [{
                    "expire": 89,
                    "name": "blacklist"
                }]
        },
        "return": "OK"
    }

Examples
--------

Creating a SSH blacklist
^^^^^^^^^^^^^^^^^^^^^^^^

Below is an example of rules incoming to a SSH server.

The first 2 rules match on a SSH software version often used in bots.
They drop the traffic and create an 'xbit' 'badssh' for the source ip.
It expires in an hour::

    drop ssh any any -> $MYSERVER 22 (msg:"DROP libssh incoming";   \
      flow:to_server,established; ssh.softwareversion:"libssh";     \
      xbits:set, badssh, track ip_src, expire 3600; sid:4000000005;)
    drop ssh any any -> $MYSERVER 22 (msg:"DROP PUTTY incoming";    \
      flow:to_server,established; ssh.softwareversion:"PUTTY";      \
      xbits:set, badssh, track ip_src, expire 3600; sid:4000000007;)

Then the following rule simply drops any incoming traffic to that server
that is on that 'badssh' list::

    drop ssh any any -> $MYSERVER 22 (msg:"DROP BLACKLISTED";       \
      xbits:isset, badssh, track ip_src; sid:4000000006;)

