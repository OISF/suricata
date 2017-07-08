Adding Your Own Rules
=====================

If you would like to create a rule yourself and use it with Suricata,
this guide might be helpful.

Start creating a file for your rule. Type for example the following in
your console:

::

  sudo nano local.rules

Write your rule, see :doc:`../rules/intro` and save it.

Open yaml

::

  sudo nano /etc/suricata/suricata.yaml

and make sure your local.rules file is added to the list of rules.

Now, run Suricata and see if your rule is being loaded.

::

  suricata -c /etc/suricata/suricata.yaml -i wlan0

If your rule failed to load, check if you have made a mistake anywhere
in the rule. Mind the details; look for mistakes in special
characters, spaces, capital characters etc.

Next, check if your log-files are enabled in suricata.yaml.

If you had to correct your rule and/or modify yaml, you have to
restart Suricata.

If you see your rule is successfully loaded, you can double check your
rule by doing something that should trigger it.

Enter:

::

  tail -f /var/log/suricata/fast.log

If you would make a rule like this:

::

  alert http any any -> any any (msg:"Do not read gossip during work";
  content:"Scarlett"; nocase; classtype:policy-violation; sid:1; rev:1;)

Your alert should look like this:

::

  09/15/2011-16:50:27.725288  [**] [1:1:1] Do not read gossip during work [**]
  [Classification: Potential Corporate Privacy Violation] [Priority: 1] {TCP} 192.168.0.32:55604 -> 68.67.185.210:80

Testing rules with Scapy
=====================

Scapy, A nefty python module to forge/sniff packets among other things, can be used to to test rules.
for example consider the following rule from The Emerging Threats rules:

::

  alert udp any any -> $HOME_NET 139 (msg:"ET NETBIOS Microsoft Windows NETAPI Stack Overflow Inbound
  - MS08-067 (8)"; content:"|20 00|"; content:"|C8 4F 32 4B 70 16 D3 01 12 78 5A 47 BF 6E E1 88|"; 
  content:"../../"; reference:url,www.microsoft.com/technet/security/Bulletin/MS08-067.mspx; 
  reference:cve,2008-4250; reference:url,www.kb.cert.org/vuls/id/827267; reference:url,
  doc.emergingthreats.net/bin/view/Main/2008697; classtype:attempted-admin; sid:2008697; rev:5;)

and to trigger it with the simple following pythong script:

::

  #!/usr/bin/python
  from scapy.all import *
  ip = IP(src="192.168.1.100", dst="192.168.1.3")
  udp=UDP(dport=139,sport=12532)
  payload="\x20\x00\xC8\x4F\x32\x4B\x70\x16\xD3\x01\x12\x78\x5A\x47\xBF\x6E\xE1\x88../../"
  send(ip/udp/payload)
  
the alert in /var/log/suricata/fast.log should look like this:

::

  07/06/2017-16:15:52.731917  [**] [1:2008697:5] ET NETBIOS Microsoft Windows NETAPI Stack 
  Overflow Inbound - MS08-067 (8) [**] [Classification: Attempted Administrator Privilege 
  Gain] [Priority: 1] {UDP} 192.168.1.100:12532 -> 192.168.8.3:139
