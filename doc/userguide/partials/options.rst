.. Start with the most common basic options.

.. option:: -h

   Display a brief usage overview.

.. option:: -V

   Displays the version of Suricata.

.. option:: -c <path>

   Path to configuration file.

.. option:: -T

   Test configuration.

.. option:: -v

   The -v option enables more verbosity of Suricata's output. Supply
   multiple times for more verbosity.

.. Basic input options.

.. option:: -r <path>

   Run in pcap offline mode reading files from pcap file.

.. option::  -i <interface>

   After the -i option you can enter the interface card you would like
   to use to sniff packets from.  This option will try to use the best
   capture method available.

.. option:: --pcap[=<device>]

   Run in PCAP mode. If no device is provided the interfaces
   provided in the *pcap* section of the configuration file will be
   used.
   
.. option:: --af-packet[=<device>]

   Enable capture of packet using AF_PACKET on Linux. If no device is
   supplied, the list of devices from the af-packet section in the
   yaml is used.

.. option:: -q <queue id>

   Run inline of the NFQUEUE queue ID provided. May be provided
   multiple times.

.. Back to other basic options.

.. option:: -s <filename.rules>

   With the -s option you can set a file with signatures, which will
   be loaded together with the rules set in the yaml.

.. option:: -S <filename.rules>

   With the -S option you can set a file with signatures, which will
   be loaded exclusively, regardless of the rules set in the yaml.

.. option:: -l <directory>

   With the -l option you can set the default log directory. If you
   already have the default-log-dir set in yaml, it will not be used
   by Suricata if you use the -l option. It will use the log dir that
   is set with the -l option. If you do not set a directory with
   the -l option, Suricata will use the directory that is set in yaml.

.. option:: -D

   Normally if you run Suricata on your console, it keeps your console
   occupied. You can not use it for other purposes, and when you close
   the window, Suricata stops running.  If you run Suricata as deamon
   (using the -D option), it runs at the background and you will be
   able to use the console for other tasks without disturbing the
   engine running.

.. option:: --runmode <runmode>

   With the *--runmode* option you can set the runmode that you would
   like to use. This command line option can override the yaml runmode
   option.

   Runmodes are: *workers*, *autofp* and *single*.

   For more information about runmodes see :doc:`Runmodes
   </performance/runmodes>` in the user guide.

.. option:: -F <bpf filter file>

   Use BPF filter from file.

.. option:: -k [all|none]

   Force (all) the checksum check or disable (none) all checksum
   checks.

.. option:: --user=<user>

   Set the process user after initialization. Overrides the user
   provided in the *run-as* section of the configuration file.

.. option:: --group=<group>

   Set the process group to group after initialization. Overrides the
   group provided in the *run-as* section of the configuration file.

.. option:: --pidfile <file>

   Write the process ID to file. Overrides the *pid-file* option in
   the configuration file and forces the file to be written when not
   running as a daemon.

.. option:: --init-errors-fatal

   Exit with a failure when errors are encountered loading signatures.

.. option:: --disable-detection

   Disable the detection engine.

.. Information options.
   
.. option:: --dump-config

   Dump the configuration loaded from the configuration file to the
   terminal and exit.

.. option:: --build-info

   Display the build information the Suricata was built with.

.. option:: --list-app-layer-protos

   List all supported application layer protocols.

.. option:: --list-keywords=[all|csv|<kword>]

   List all supported rule keywords.

.. option:: --list-runmodes

   List all supported run modes.

.. Advanced options.

.. option:: --set <key>=<value>

   Set a configuration value. Useful for overriding basic
   configuration parameters in the configuration. For example, to
   change the default log directory::

     --set default-log-dir=/var/tmp

.. option:: --engine-analysis

   Print reports on analysis of different sections in the engine and
   exit. Please have a look at the conf parameter engine-analysis on
   what reports can be printed

.. option:: --unix-socket=<file>

   Use file as the Suricata unix control socket. Overrides the
   *filename* provided in the *unix-command* section of the
   configuration file.

.. Advanced input options.

.. option:: --pcap-buffer-size=<size>

   Set the size of the PCAP buffer (0 - 2147483647).

.. option:: --netmap[=<device>]

   Enable capture of packet using NETMAP on FreeBSD or Linux. If no
   device is supplied, the list of devices from the netmap section
   in the yaml is used.

.. option:: --pfring[=<device>]

   Enable PF_RING packet capture. If no device provided, the devices in
   the Suricata configuration will be used.
  
.. option:: --pfring-cluster-id <id>

   Set the PF_RING cluster ID.
   
.. option:: --pfring-cluster-type <type>

   Set the PF_RING cluster type (cluster_round_robin, cluster_flow).

.. option:: -d <divert-port>

   Run inline using IPFW divert mode.

.. option:: --dag <device>

   Enable packet capture off a DAG card. If capturing off a specific
   stream the stream can be select using a device name like
   "dag0:4". This option may be provided multiple times read off
   multiple devices and/or streams.
	    
.. option:: --napatech

   Enable packet capture using the Napatech Streams API.

.. option:: --mpipe

   Enable packet capture using the TileGX mpipe interface.

.. option:: --erf-in=<file>

   Run in offline mode reading the specific ERF file (Endace
   extensible record format).

.. option:: --simulate-ips

   Simulate IPS mode when running in a non-IPS mode.
