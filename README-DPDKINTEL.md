# suricata
Mirror of the official OISF Suricata git repository to support Intel DPDK

DESIGN FOR SURICATA-DPDK:-
=========================

Following are changes added for DPDK support into Suricata platform

a) CONFIGURE:
1.	“—enable-dpdkintel” is argument in configure script to start off dpdk processing. 
2.	Check for target os is linux or not
3.	Add compiler flag for Makefile “HAVE_DPKDINTEL”
4.	Add support for check for RTE_SDK and RTE_TARGET paths
5.	Add support user defined custom libraries and include folders.
6.	Linker support for driver init for Intel 1G interface
7.	Disable support for af-packet.
Note: execute automake to generate new configure script with changes.

b) MAKE: 
On execution of “configure” the template “Makefile.in” is executed with appropriate flags. For INTEL-DPDK following changes get added
1.	am__append_1 to append all source and header files.
2.	am__objects_1 to process DPDK Intel specific files.
3.	DPDKINTEL_LDADD to load DPDK load flags to gcc

c) RUN MODE:
Current design just focuses on worker mode for DPDK-INTEL. As one complete thread acquires, decodes, streams, detects and outputs the 
packets in IPS/IDS/BYPASS. Worker mode is configuration used for 10G cases too.

FUNCTIONAL WALK THROUGH
1.	Added “--list-dpdkintel-ports, --dpdkintel“ to “usage” and 
2.	Added DPDKINTEL to “SCPrintBuildInfo“
3.	Added “TmModuleReceiveDpdkRegister, TmModuleDecodeDpdkRegister“ to RegisterAllModules“
4.	Disabled support for PCAP if run mode is DPDKINTEL.
5.	Added runmode “RUNMODE_LIST_DPDKINTEL_PORTS“via ListDpdkIntelPorts
6.	Executed in main
a.	dpdkEalInit
b.	ParseDpdkConfig
c.	validateMap
d.	dpdkConfSetup
e.	launchDpdkFrameParser
f.	rte_eal_mp_wait_lcore

Interfaces are loaded with DPDK User IO driver which helps to acquire traffic to user space via POLL mode driver.

DESIGN
Total worker threads, CPU affinity with available spare cores are calculated to check; if enough number of cores are present to dpdkIntel 
Receive traffic from interface is run on dedicated DPDK lcore. The packets are forwarded onto PacketAcquireLoop function via Ring Buffer. 
This is close to pipeline modeling; except the receiving thread does not run on same core via packet affinity (YAML configuration). 
Scheduling of worker threads fetches packets by dequeuing the ring buffer associated to worker thread in user space. 

Following are couple of validation done in background
1.	Check for Link speed setup for IPS pairs.
2.	Fetch the CPU affinity for Suricata
3.	Cross check if CPU availability with Intel Cores for DPDK.
4.	Assign 1 DPDK core for 10 and 100 MB interface for IPS|IDS|BYPASS.
5.	Assign 1 DPDK core for 10G interfaces.


Completed:
1.	Added DPDK 1G interface processing to Suricata baseline 2.0.8
2.	Achieved more than 50% more packet processing from 64 to 1500 byte packet size compared to AF workers.
3.	Tested with Hit and no Hit pattern matching rules
4.	Operation mode support for IDS and IPS.
5.	Added separate register mode for dpdk-intel

To Do:
1.	Support for 10G and 40G INTEL NW cards.
2.	Add more than 1 queue for Interfaces (more dpdk core per interface)
3.	Benchmark with dpdk-core with isolate kernel boot args.
4.	Add pre-processor parsing for lcore threads.
5.	Pre-ACL lookup before Suricata worker processing.
6.	Debug stats for debug mode in DPDK-INTEL.
7.	Virtual Interface.
