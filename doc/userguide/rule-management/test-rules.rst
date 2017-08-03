Testing Rules
=============

In this tutorial we will craft packets that can trigger suricata's rules, using scapy (a python module which can be ran in interactive mode as well), scapy is a great Network Packet Manipulation tool (it can forge/sniff packets) for more information on how to use it check out scapy's main website: http://www.secdev.org/projects/scapy/

First lets create a simple/small rule in /etc/suricata/rules/local.rules
say for example:
::

  alert udp any any -> any any (msg:"A Testing rule fired"; content:"Suricata"; nocase; sid:1; rev:1;)

to create a packet that will trigger the rule above, run scapy in a terminal (it will need root Privileges to send packets):

::

  # scapy
  WARNING: No route found for IPv6 destination :: (no default route?)
  Welcome to Scapy (2.2.0)
  >>>

first we define a source/destination IP addresses, then source/destination ports, a payload and we send the packet we made:

::

  >>> ip=IP(src="192.168.2.1", dst="172.16.23.1")
  >>> udp=UDP(dport=1542, sport=8415)
  >>> payload="Suricata"
  >>> send(ip/udp/payload)
  .
  Sent 1 packets.

by now there should an alert in /var/log/suricata/fast.log that looks kind of like this:
:: 
  08/01/2017-16:15:52.731917  [**] [1:1] A Testing rule fired [**] ... {UDP} 192.168.2.1:1542 -> 172.16.23.1:8415



 
