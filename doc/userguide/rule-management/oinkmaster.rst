Rule Management with Oinkmaster
===============================

.. note:: ``suricata-update`` is the official and recommended way to
          update and manage rules and rulesets. See :doc:`suricata-update`

It is possible to download and install rules manually, but there is a
much easier and quicker way to do so. There are special programs which
you can use for downloading and installing rules. There is for example
`Pulled Pork <https://github.com/shirkdog/pulledpork>`_ and
`Oinkmaster <http://oinkmaster.sourceforge.net/>`_. In this documentation
the use of Oinkmaster will be described.

To install Oinkmaster, enter:

::

  sudo apt-get install oinkmaster

There are several rulesets. There is for example Emerging Threats (ET)
Emerging Threats Pro and VRT.  In this example we are using Emerging
Threats.

Oinkmaster has to know where the rules an be found. These rules can be found at:

::

  https://rules.emergingthreats.net/open/suricata-3.2/emerging.rules.tar.gz

open oinkmaster.conf to add this link by entering:

::

  sudo nano /etc/oinkmaster.conf

Place a # in front of the url that is already there and add the new url like this:

.. image:: oinkmaster/oinkmasterconf.png

(Close oinkmaster.conf by pressing ctrl x, followed by y and enter. )

The next step is to create a directory for the new rules. Enter:

::

  sudo mkdir /etc/suricata/rules


Next enter:

::

  cd /etc
  sudo oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules

In the new rules directory a classification.config and a
reference.config can be found. The directories of both have to be
added in the suricata.yaml file. Do so by entering:

::

  sudo nano /etc/suricata/suricata.yaml

And add the new file locations instead of the file locations already
present, like this:

.. image:: oinkmaster/suricata_yaml.png

To see if everything works as pleased, run Suricata:

::

  suricata -c /etc/suricata/suricata.yaml -i wlan0 (or eth0)

You will notice there are several rule-files Suricata tries to load,
but are not available. It is possible to disable those rule-sets in
suricata.yaml by deleting them or by putting a # in front of them.  To
stop Suricata from running, press ctrl c.

Emerging Threats contains more rules than loaded in Suricata. To see
which rules are available in your rules directory, enter:

::

  ls /etc/suricata/rules/*.rules

Find those that are not yet present in suricata.yaml and add them in
yaml if desired.

You can do so by entering :

::

  sudo nano /etc/suricata/suricata.yaml

If you disable a rule in your rule file by putting a # in front of it,
it will be enabled again the next time you run Oinkmaster. You can
disable it through Oinkmaster instead, by entering the following:

::

  cd /etc/suricata/rules

and find the sid of the rule(s) you want to disable.

Subsequently enter:

::

  sudo nano /etc/oinkmaster.conf

and go all the way to the end of the file.
Type there:

::

  disablesid 2010495

Instead of 2010495, type the sid of the rule you would like to
disable. It is also possible to disable multiple rules, by entering
their sids separated by a comma.

If you run Oinkmaster again, you can see the amount of rules you have
disabled.  You can also enable rules that are disabled by default. Do
so by entering:

::

  ls /etc/suricata/rules

In this directory you can see several rule-sets
Enter for example:

::

  sudo nano /etc/suricata/rules/emerging-malware.rules

In this file you can see which rules are enabled en which are not.
You can not enable them for the long-term just by simply removing
the #. Because each time you will run Oinkmaster, the rule will be
disabled again.  Instead, look up the sid of the rule you want to
enable. Place the sid in the correct place of oinkmaster.config:

::

  sudo nano /etc/oinkmaster.conf

do so by typing:

::

  enablesid: 2010495

Instead of 2010495, type the sid of the rule you would like to to
enable. It is also possible to enable multiple rules, by entering
their sids separated by a comma.

In oinkmaster.conf you can modify rules. For example, if you use
Suricata as inline/IPS and you want to modify a rule that sends an
alert when it matches and you would like the rule to drop the packet
instead, you can do so by entering the following:

::

  sudo nano oinkmaster.conf

At the part where you can modify rules, type:

::

  modifysid 2010495 "alert" | "drop"

The sid 2010495 is an example. Type the sid of the rule you desire to
change, instead.

Rerun Oinkmaster to notice the change.

Updating your rules
~~~~~~~~~~~~~~~~~~~

If you have already downloaded a ruleset (in the way described in this
file), and you would like to update the rules, enter:

::

  sudo oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules

It is recommended to update your rules frequently. Emerging Threats is
modified daily, VRT is updated weekly or multiple times a week.
