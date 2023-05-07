.. Start with the most common basic options.

.. option:: -h

   Display a brief usage overview.

.. option:: -V

   Displays the version of Suricata.

.. option:: -c <path>

   Path to configuration file.

.. option:: --include <path>

   Additional configuration files to include. Multiple additional
   configuration files can be provided and will be included in the
   order specified on the command line.  These additional configuration
   files are loaded as if they existed at the end of the main
   configuration file.

   Example including one additional file::

     --include /etc/suricata/other.yaml

   Example including more than one additional file::

     --include /etc/suricata/other.yaml --include /etc/suricata/extra.yaml

.. option:: -T

   Test configuration.

.. _cmdline-option-v:

.. option:: -v

   Increase the verbosity of the Suricata application logging by
   increasing the log level from the default. This option can be
   passed multiple times to further increase the verbosity.

   - -v: INFO
   - -vv: PERF
   - -vvv: CONFIG
   - -vvvv: DEBUG

   This option will not decrease the log level set in the
   configuration file if it is already more verbose than the level
   requested with this option.

.. Basic input options.

.. option:: -r <path>

   Run in pcap offline mode (replay mode) reading files from pcap file. If
   <path> specifies a directory, all files in that directory will be processed
   in order of modified time maintaining flow state between files.

.. option:: --pcap-file-continuous

   Used with the -r option to indicate that the mode should stay alive until
   interrupted. This is useful with directories to add new files and not reset
   flow state between files.

.. option:: --pcap-file-recursive

   Used with the -r option when the path provided is a directory.  This option
   enables recursive traversal into subdirectories to a maximum depth of 255.
   This option cannot be combined with --pcap-file-continuous.  Symlinks are
   ignored.

.. option:: --pcap-file-delete

   Used with the -r option to indicate that the mode should delete pcap files
   after they have been processed. This is useful with pcap-file-continuous to
   continuously feed files to a directory and have them cleaned up when done. If
   this option is not set, pcap files will not be deleted after processing.

.. option::  -i <interface>

   After the -i option you can enter the interface card you would like
   to use to sniff packets from.  This option will try to use the best
   capture method available. Can be used several times to sniff packets from
   several interfaces.

.. option:: --pcap[=<device>]

   Run in PCAP mode. If no device is provided the interfaces
   provided in the *pcap* section of the configuration file will be
   used.
   
.. option:: --af-packet[=<device>]

   Enable capture of packet using AF_PACKET on Linux. If no device is
   supplied, the list of devices from the af-packet section in the
   yaml is used.

.. option:: --af-xdp[=<device>]

   Enable capture of packet using AF_XDP on Linux. If no device is
   supplied, the list of devices from the af-xdp section in the
   yaml is used.

.. option:: -q <queue id>

   Run inline of the NFQUEUE queue ID provided. May be provided
   multiple times.

.. Back to other basic options.

.. option:: -s <filename.rules>

   With the -s option you can set a file with signatures, which will
   be loaded together with the rules set in the yaml.

   It is possible to use globbing when specifying rules files.
   For example, ``-s '/path/to/rules/*.rules'``

.. option:: -S <filename.rules>

   With the -S option you can set a file with signatures, which will
   be loaded exclusively, regardless of the rules set in the yaml.

   It is possible to use globbing when specifying rules files.
   For example, ``-S '/path/to/rules/*.rules'``

.. option:: -l <directory>

   With the -l option you can set the default log directory. If you
   already have the default-log-dir set in yaml, it will not be used
   by Suricata if you use the -l option. It will use the log dir that
   is set with the -l option. If you do not set a directory with
   the -l option, Suricata will use the directory that is set in yaml.

.. option:: -D

   Normally if you run Suricata on your console, it keeps your console
   occupied. You can not use it for other purposes, and when you close
   the window, Suricata stops running.  If you run Suricata as daemon
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

.. option:: --strict-rule-keywords[=all|<keyword>|<keywords(csv)]

   Applies to: classtype, reference and app-layer-event.

   By default missing reference or classtype values are warnings and
   not errors. Additionally, loading outdated app-layer-event events are
   also not treated as errors, but as warnings instead.

   If this option is enabled these warnings are considered errors.

   If no value, or the value 'all', is specified, the option applies to
   all of the keywords above. Alternatively, a comma separated list can
   be supplied with the keyword names it should apply to.

.. option:: --disable-detection

   Disable the detection engine.

.. option:: --disable-hashing

   Disable support for hash algorithms such as md5, sha1 and sha256.

   By default hashing is enabled. Disabling hashing will also disable some
   Suricata features such as the filestore, ja3, and rule keywords that use hash
   algorithms.

.. Information options.
   
.. option:: --dump-config

   Dump the configuration loaded from the configuration file to the
   terminal and exit.

.. option:: --dump-features

   Dump the features provided by Suricata modules and exit. Features
   list (a subset of) the configuration values and are intended to
   assist with comparing provided features with those required by
   one or more rules.

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
   configuration parameters. For example, to change the default log
   directory::

     --set default-log-dir=/var/tmp

   This option cannot be used to add new entries to a list in the
   configuration file, such as a new output. It can only be used to
   modify a value in a list that already exists.

   For example, to disable the ``eve-log`` in the default
   configuration file::

     --set outputs.1.eve-log.enabled=no

   Also note that the index values may change as the ``suricata.yaml``
   is updated.

   See the output of ``--dump-config`` for existing values that could
   be modified with their index.

.. option:: --engine-analysis

   Print reports on analysis of different sections in the engine and
   exit. Please have a look at the conf parameter engine-analysis on
   what reports can be printed

.. option:: --unix-socket=<file>

   Use file as the Suricata unix control socket. Overrides the
   *filename* provided in the *unix-command* section of the
   configuration file.

.. option:: --reject-dev=<device>

   Use *device* to send out RST / ICMP error packets with
   the *reject* keyword.

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

.. option:: --erf-in=<file>

   Run in offline mode reading the specific ERF file (Endace
   extensible record format).

.. option:: --simulate-ips

   Simulate IPS mode when running in a non-IPS mode.
