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
