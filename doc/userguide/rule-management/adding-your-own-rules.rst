Adding Your Own Rules
=====================

If you would like to create a rule yourself and use it with Suricata,
this guide might be helpful.

Start creating a file for your rule. Use one of the following examples in
your console/terminal window:

::

  sudo nano local.rules
  sudo vim local.rules

Write your rule, see :doc:`../rules/intro` and save it.

Update the Suricata configuration file so your rule is included. Use
one of the following examples:

::

  sudo nano /etc/suricata/suricata.yaml
  sudo vim /etc/suricata/suricata.yaml

and make sure your local.rules file is added to the list of rules: ::

    default-rule-path: /usr/local/etc/suricata/rules

    rule-files:
      - suricata.rules
      - /path/to/local.rules

Now, run Suricata and see if your rule is being loaded.

::

  suricata -c /etc/suricata/suricata.yaml -i wlan0

If the rule failed to load, Suricata will display as much information as
it has when it deemed the rule un-loadable. Pay special attention to the
details: look for mistakes in special characters, spaces, capital characters,
etc.

Next, check if your log-files are enabled in the Suricata configuration file
``suricata.yaml``.

If you had to correct your rule and/or modify Suricata's YAML configuration
file, you'll have to restart Suricata.

If you see your rule is successfully loaded, you can double check your
rule by doing something that should trigger it.

By default, Suricata will log alerts to two places

- ``eve.json``
- ``fast.log``

These files will be located in the log output directory which is set by
one of two methods:

1. Suricata configuration file: see ``default-log-dir`` for the name of the directory
2. Suricata command line: Using ``-l /path/to/log-dir`` creates log files in the named
   directory.

The following example assumes that the log directory is named ``/var/log/suricata`` ::

  tail -f /var/log/suricata/fast.log

If you would make a rule like this: ::

  alert http any any -> any any (msg:"Do not read gossip during work";
  content:"Scarlett"; nocase; classtype:policy-violation; sid:1; rev:1;)

Your alert should look like this: ::

  09/15/2011-16:50:27.725288  [**] [1:1:1] Do not read gossip during work [**]
  [Classification: Potential Corporate Privacy Violation] [Priority: 1] {TCP} 192.168.0.32:55604 -> 68.67.185.210:80
