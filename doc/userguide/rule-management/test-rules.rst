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
  08/04/2017-04:34:32.668027  [**] [1:1:1] A Testing rule fired [**] [Classification: (null)] [Priority: 3] {UDP} 192.168.2.1:8415 -> 172.16.23.1:1542



Testing existing Rules
======================

by now we should try to test an already existing rule, like for example the ones that come in Emerging Threat Rules.
lets look inside /etc/suricata/rules/emerging-netbios.rules  for example, this rule:
::
  alert udp any any -> $HOME_NET 139 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (8)"; content:"|20 00|"; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; content:"../../"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,doc.emergingthreats.net/bin/view/Main/2008697; classtype:attempted-admin; sid:2008697; rev:5;)
   
this rule would trigger if a udp packet coming from any host to a host inside our network on port 139, containing the following data in the payload:
::
  20 00 C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88 ../../
 
to trigger that rule with scapy:
::
  >>> ip=IP(src="123.23.23.22", dst="192.168.2.100")
  >>> udp=UDP(dport=139, sport=51339)
  >>> payload="\x20\x00\xC8\x4F\x32\x4B\x70\x16\xD3\x01\x12\x78\x5A\x47\xBF\x6E\xE1\x88../../"
  >>> send(ip/udp/payload)
  .
  Sent 1 packets.
  >>> 

and in the /var/log/suricata/fast.log we should see the following:
::
  08/04/2017-05:02:08.587897  [**] [1:2008697:5] ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound - MS08-067 (8) [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {UDP} 123.23.23.22:51339 -> 192.168.2.100:139


