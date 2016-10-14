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

Example: create a SSH blacklist
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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
