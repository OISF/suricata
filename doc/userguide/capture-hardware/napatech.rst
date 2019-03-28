Napatech
========

Contents
--------
	* Introduction

	* Package Installation

	* Basic Configuration

	* Advanced Multithreaded Configuration

Introduction
------------

Napatech packet capture accelerator cards can greatly improve the performance of your Suricata deployment using these
hardware based features:

	* On board burst buffering (up to 12GB)

	* Zero-copy kernel bypass DMA

	* Non-blocking PCIe performance

	* Port merging

	* Load distribution to up 128 host buffers

	* Precise timestamping

	* Accurate time synchronization

The package uses a proprietary shell script to handle the installation process.
In either case, gcc, make and the kernel header files are required to compile the kernel module and
install the software.

Package Installation
--------------------

*Note that make, gcc, and the kernel headers are required for installation*

*Root privileges are also required*

The latest driver and tools installation package can be downloaded from: https://www.napatech.com/downloads.

*Note that you will be prompted to install the Napatech libpcap library. Answer "yes" if you would like to
use the Napatech card to capture packets in Wireshark, tcpdump, or another pcap based application.
Libpcap is not needed for Suricata as native Napatech API support is included*

Red Hat Based Distros::

 $ yum install kernel-devel-$(uname -r) gcc make
	$ ./package_install_3gd.sh

Debian Based Distros::

 $ apt-get install linux-headers-$(uname .r) gcc make
	$ ./package_install_3gd.sh

To complete installation for all distros ntservice::

	$ /opt/napatech3/bin/ntstart.sh -m

Suricata Installation
---------------------

After downloading and extracting the Suricata tarball, you need to run configure to enable Napatech support and
prepare for compilation::

	$ ./configure --enable-napatech --with-napatech-includes=/opt/napatech3/include --with-napatech-libraries=/opt/napatech3/lib
	$ make
	$ make install-full

Suricata configuration
----------------------

Now edit the suricata.yaml file to configure the system. There are three ways
the system can be configured:

  1. Auto-config without cpu-affinity: In this mode you specify the stream
  configuration in suricata.yaml file and allow the threads to
  roam freely. This is good for single processor systems where NUMA node
  configuration is not a performance concern.

  2. Auto-config with cpu-affinity: In this mode you use the cpu-affinity
  of the worker threads to control the creation and configuration of streams.
  One stream and one worker thread will be created for each cpu identified in
  suricata.yaml. This is best in systems with multiple NUMA nodes (i.e.
  multi-processor systems) as the NUMA node of the host buffers is matched
  to the core on which the thread is running.

  3. Manual-config (legacy): In this mode the underlying Napatech streams are configured
  by issuing NTPL commands prior to running suricata. Suricata then connects
  to the existing streams on startup.

Example Configuration - Auto-config without cpu-affinity:
---------------------------------------------------------

If cpu-affinity is not used it is necessary to explicitly define the streams in
the Suricata configuration file. To use this option the following options should
be set in the suricata configuration file:

  1. Turn off cpu-affinity

  2. Enable the napatech "auto-config" option

  3. Specify the streams that should be created on startup

  4. Specify the ports that will provide traffic to suricata

  5. Specify the hashmode used to distribute traffic to the streams

Below are the options to set::

    threading:
      set-cpu-affinity: no
        .
        .
        .
    napatech:
        auto-config: yes
        streams: ["0-3"]
        ports: [all]
        hashmode: hash5tuplesorted

Now modify ntservice.ini. You also need make sure that you have allocated enough
host buffers in ntservice.ini for the streams. It's a good idea to also set the
TimeSyncReferencePriority. To do this make the following changes to ntservice.ini:

    HostBuffersRx = [4,16,-1] # [number of host buffers, Size(MB), NUMA node]
    TimeSyncReferencePriority = OSTime	# Timestamp clock synchronized to the OS

Stop and restart ntservice after making changes to ntservice::

	$ /opt/napatech3/bin/ntstop.sh
	$ /opt/napatech3/bin/ntstart.sh

Now you are ready to start suricata::

 $ suricata -c /usr/local/etc/suricata/suricata.yaml --napatech --runmode workers

Example Configuration - Auto-config with cpu-affinity:
------------------------------------------------------

This option will create a single worker-thread and stream for each CPU defined in the
worker-cpu-set. To use this option make the following changes to suricata.yaml:

1. Turn on cpu-affinity
2. Specify the worker-cpu-set
3. Enable the napatech "auto-config" option
4. Specify the ports that will provide traffic to suricata
5. Specify the hashmode that will be used to control the distribution of
   traffic to the different streams/cpus.

When you are done it should look similar to this::

  threading:
    set-cpu-affinity: yes
    cpu-affinity:
      management-cpu-set:
        cpu: [ 0 ]
      receive-cpu-set:
        cpu: [ 0 ]
      worker-cpu-set:
        cpu: [ all ]
        .
        .
        .
  napatech:
    auto-config: yes
    ports: [all]
    hashmode: hash5tuplesorted

Prior to running Suricata in this mode you also need to configure a sufficient
number of host buffers on each NUMA node. So, for example, if you have a two
processor server with 32 total cores and you plan to use all of the cores you
will need to allocate 16 host buffers on each NUMA node. It is also desirable
to set the Napatech cards time source to the OS.

To do this make the following changes to ntservice.ini::

    TimeSyncReferencePriority = OSTime	# Timestamp clock synchronized to the OS
    HostBuffersRx = [16,16,0],[16,16,1] # [number of host buffers, Size(MB), NUMA node]

Stop and restart ntservice after making changes to ntservice::

	$ /opt/napatech3/bin/ntstop.sh -m
	$ /opt/napatech3/bin/ntstart.sh -m

Now you are ready to start suricata::

    $ suricata -c /usr/local/etc/suricata/suricata.yaml --napatech --runmode workers

Example Configuration - Manual Configuration
--------------------------------------------

For Manual Configuration the Napatech streams are created by running NTPL
commands prior to running Suricata. In this example we will setup the Napatech
capture accelerator to merge all physical ports, and then distribute the merged
traffic to four streams that Suricata will ingest.

The steps for this configuration are:
  1. Disable the napatech auto-config option in suricata.yaml
  2. Specify the streams that suricata is to use in suricata.yaml
  3. Create a file with NTPL commands to create the underlying Napatech streams.

First suricata.yaml should be configured similar to the following::

    napatech:
      auto-config: no
      streams: ["0-3"]

Next you need to make sure you have enough host buffers defined in ntservice.ini. As
it's also a good idea to set up the TimeSync. Here are the lines to change::

	TimeSyncReferencePriority = OSTime	# Timestamp clock synchronized to the OS
	HostBuffersRx = [4,16,-1]		# [number of host buffers, Size(MB), NUMA node]

Stop and restart ntservice after making changes to ntservice::

	$ /opt/napatech3/bin/ntstop.sh
	$ /opt/napatech3/bin/ntstart.sh

Now that ntservice is running we need to execute a few NTPL (Napatech Programming Language)
commands to complete the setup. Create a file will the following commands::

	Delete=All				# Delete any existing filters
	Assign[streamid=(0..3)]= all	# Assign all phisical ports to stream ID 0

Next execute those command using the ntpl tool::

	$ /opt/napatech3/bin/ntpl -f <my_ntpl_file>

Now you are ready to start suricata::

	$ suricata -c /usr/local/etc/suricata/suricata.yaml --napatech --runmode workers

It is possible to specify much more elaborate configurations using this option. Simply by
creating the appropriate NTPL file and attaching suricata to the streams.

Counters
--------

For each stream that is being processed the following counters will be output in stats.log:

- nt<streamid>.pkts - The number of packets recieved by the stream.

- nt<streamid>.bytes - The total bytes received by the stream.

- nt<streamid>.drop - The number of packets that were dropped from this stream due to buffer overflow conditions.

If hba is enabled the following counter will also be provided:

- nt<streamid>.hba_drop - the number of packets dropped because the host buffer allowance high-water mark was reached.

In addition to counters host buffer utilization is tracked and logged. This is also useful for
debugging. Log messages are output for both Host and On-Board buffers when reach 25, 50, 75
percent of utilization. Corresponding messages are output when utilization decreases.

Debugging:

For debugging configurations it is useful to see what traffic is flowing as well as what streams are
created and receiving traffic. There are two tools in /opt/napatech3/bin that are useful for this:

 - monitoring: this tool will, among other things, show what traffic is arriving at the port interfaces.

 - profiling: this will show  host-buffers, streams and traffic flow to the streams.

If suricata terminates abnormally stream definitions, which are normally removed at shutdown, may remain in effect.
If this happens they can be cleared by issuing the "delete=all" NTPL command as follows::

    # /opt/napatech3/bin/ntpl -e "delete=all"

Napatech configuration options:
-------------------------------

These are the Napatech options available in the suricata configuration file::

  napatech:
    # The Host Buffer Allowance for all streams
    # (-1 = OFF, 1 - 100 = percentage of the host buffer that can be held back)
    # This may be enabled when sharing streams with another application.
    # Otherwise, it should be turned off.
    #hba: -1

    # When use_all_streams is set to "yes" the initialization code will query
    # the Napatech service for all configured streams and listen on all of them.
    # When set to "no" the streams config array will be used.
    #
    # This option necessitates running the appropriate NTPL commands to create
    # the desired streams prior to running suricata.
    #use-all-streams: no

    # The streams to listen on when cpu-affinity or auto-config is disabled.
    # This can be either:
    #   a list of individual streams (e.g. streams: [0,1,2,3])
    # or
    #   a range of streams (e.g. streams: ["0-3"])
    #
    #streams: ["0-7"]
    #
    # When auto-config is enabled the streams will be created and assigned to the
    # NUMA node where the thread resides automatically. The streams will be created
    # according to the number of worker threads specified in the worker cpu set.
    # (I.e. the value of threading.cpu-affinity.worker-cpu-set.cpu.)
    #
    # This option cannot be used simultaneous with "use-all-streams".
    #
    auto-config: yes
    #
    # Ports indicates which napatech ports are to be used in auto-config mode.
    # these are the port ID's of the ports that will merged prior to the traffic
    # being distributed to the streams.
    #
    # This can be specified in any of the following ways:
    #
    #   a list of individual ports (e.g. ports: [0,1,2,3])
    #
    #   a range of ports (e.g. ports: [0-3])
    #
    #   "all" to indicate that all ports are to be merged together
    #   (e.g. ports: [all])
    #
    # This has no effect if auto-config is disabled.
    #
    ports: [all]
    #
    # When auto-config is enabled the hashmode specifies the algorithm for
    # determining to which stream a given packet is to be delivered.
    # This can be any valid Napatech NTPL hashmode command.
    #
    # The most common hashmode commands are: hash2tuple, hash2tuplesorted,
    # hash5tuple, hash5tuplesorted and roundrobin.
    #
    # See Napatech NTPL documentation other hashmodes and details on their use.
    #
    # This has no effect if auto-config is disabled.
    #
    hashmode: hash5tuplesorted

*Note: hba is useful only when a stream is shared with another application. When hba is enabled packets will be dropped
(i.e. not delivered to suricata) when the host-buffer utilization reaches the high-water mark indicated by the hba value.
This insures that, should suricata get behind in it's packet processing, the other application will still receive all
of the packets. If this is enabled without another application sharing the stream it will result in sub-optimal packet
buffering.*

Make sure that there are enough host-buffers declared in ntservice.ini to
accommodate the number of cores/streams being used.

Support
-------

Contact a support engineer at: ntsupport@napatech.com

Napatech Documentation can be found at: https://docs.napatech.com (Click the search icon, with no search text,
to see all documents in the portal.)