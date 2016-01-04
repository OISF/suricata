Packet Profiling
================

In this guide will be explained how to enable packet profiling and use
it with the most recent code of Suricata on Ubuntu. It is based on the
assumption that you have already installed Suricata once from the GIT
repository.

Packet profiling is convenient in case you would like to know how long
packets take to be processed. It is a way to figure out why certain
packets are being processed quicker than others, and this way a good
tool for developing Suricata.

Update Suricata by following the steps from `Installation from Git
<https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Installation_from_Git>`_. Start
at the end at

::

  cd suricata/oisf
  git pull

And follow the described next steps. To enable packet profiling, make
sure you enter the following during the configuring stage:

::

  ./configure --enable-profiling

Find a folder in which you have pcaps. If you do not have pcaps yet,
you can get these with Wireshark. See `Sniffing Packets with Wireshark
<https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Sniffing_Packets_with_Wireshark>`_.

Go to the directory of your pcaps. For example:

::

  cd  ~/Desktop

With the ls command you can see the content of the folder.  Choose a
folder and a pcap file

for example:

::

  cd ~/Desktop/2011-05-05

Run Suricata with that pcap:

::

  suricata -c /etc/suricata/suricata.yaml -r log.pcap.(followed by the number/name of your pcap)

for example:

::

  suricata -c /etc/suricata/suricata.yaml -r log.pcap.1304589204
