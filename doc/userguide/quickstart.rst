Quickstart guide
================

This guide will give you a quick start to run Suricata and will focus only on
the basics. For more details read through the different more specific chapters.

Installation
------------

It's assumed that you run a recent Ubuntu release as the official PPA can be
used for the installation.

Installation steps::

    sudo add-apt-repository ppa:oisf/suricata-stable
    sudo apt update
    sudo apt install suricata jq

The dedicated PPA repository is added and after updating the index Suricata can
be installed. It's recommended to install the tool ``jq`` as well to work with
the EVE Json output which is used later in this guide.

For the installation on other systems or to use specific compile options see
:ref:`installation`.

When the installation is done you can check what version of Suricata you have
running and with what options as well as the service state::

    sudo suricata --build-info
    sudo systemctl status suricata

Basic setup
-----------

You should check on which interface Suricata should be running and also the
IP(s) of the interface::

    ip a

    2: enp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff
    inet 10.0.0.23/24 brd 10.23.0.255 scope global noprefixroute enp1s0

Use that information to configure Suricata::

    sudo vim /etc/suricata/suricata.yaml

There will be a lot of possible configuration options, we focus on the setup of
the ``HOME_NET`` variable and the network interface configuration. The
``HOME_NET`` variable should include, in most scenarios, the IP you have
configured on the interface you use to monitor and all the local networks in
use. The default already includes the RFC 1918 networks. In this example
``10.0.0.23`` is already included within ``10.0.0.0/8``. If no other networks
are used the other predefined can be removed.

In this example the interface name is ``enp1s0`` so at the ``af-packet``
section the interface name needs to match. An example interface config might
look like this:

Capture settings::

    af-packet:
        - interface: enp1s0
          cluster-id: 99
          cluster-type: cluster_flow
          defrag: yes
          use-mmap: yes
          tpacket-v3: yes

This configuration uses the most recent recommended settings for the IDS
runmode for basic setups. There are a lot of possible configuration options
which are described in dedicated chapters and are especially relevant for high
performance setups.

Signatures
----------

As Suricata uses Signatures to trigger alerts it's necessary to install those
and keep them updated. Signatures are also called rules, thus the name
rule-files. With the tool ``suricata-update`` rules can be fetched, updated and
managed to be provided for suricata.

In this guide we just run the default mode which fetches the ET Open ruleset::

    sudo suricata-update

Afterwards the rules are installed at ``/var/lib/suricata/rules`` which is also
the default at the config and uses the sole ``suricata.rules`` file.

Running Suricata
----------------

With the rules installed, Suricata can run properly and thus we restart it::

    sudo systemctl restart suricata

To make sure Suricata is running check the Suricata log::

    sudo tail /var/log/suricata/suricata.log

The last line should look like this::

    <Notice> - all 4 packet processing threads, 4 management threads initialized, engine started.

The amount of threads depends on the system and the configuration.

To see statistics the ``stats.log`` can be checked::

    sudo tail -f /var/log/suricata/stats.log

Every 20 seconds by default it will show updated informations about the current
state, like how many packets have been processed and what type of traffic was
decoded.

Alerting
--------

To test the IDS functionality of Suricata it's best to test with a signature. The signature with ID ``2100498`` from the ET Open ruleset is written specific for such test cases.

2100498::

    alert ip any any -> any any (msg:"GPL ATTACK_RESPONSE id check returned root"; content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:2100498; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)

The syntax and logic behind those signatures is covered in other chapters. This
will alert on any IP traffic that has the content within its payload. This rule
can be triggered quite easy. Before we trigger it, we will tail on the
``fast.log`` so we see the result.

Ruletrigger::

    sudo tail -f /var/log/suricata/fast.log
    curl http://testmyids.com/

The following output should now be seen in the log::

    [1:2100498:7] GPL ATTACK_RESPONSE id check returned root [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 217.160.0.187:80 -> 10.0.0.23:41618

This should include the timestamp and the IP of your system.

EVE Json
--------

The more advanced output is the EVE Json output which is explained in detail in
:ref:`Eve JSON Output <eve-json-output>`. To see what this looks like it's
recommended to use ``jq`` to parse the JSON output.

Alert::

    sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'

This will also show much more details and meta-data that are related to the
triggered alert.

Stats::

    sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="stats")|.stats.capture.kernel_packets'

This will only show the amount of packets processed.
