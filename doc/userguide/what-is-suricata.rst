What is Suricata
================
                                                                                
The Suricata Engine is an Open Source Next Generation Intrusion
Detection and Prevention Engine. This engine is not intended to just
replace or emulate the existing tools in the industry, but will bring
new ideas and technologies to the field. The Suricata Engine and the
HTP Library are available to use under the GPLv2.


IDS/IPS
-------
 
Suricata is a rule-based ID/PS engine that utilises externally
developed rule sets to monitor network traffic and provide alerts to
the system administrator when suspicious events occur. Designed to be
compatible with existing network security components, Suricata
features unified output functionality and pluggable library options to
accept calls from other applications.  The initial release of Suricata
runs on a Linux 2.6 platform that supports inline and passive traffic
monitoring configuration capable of handling multiple gigabit traffic
levels. Linux 2.4 is supported with reduced configuration
functionality, such as no inline option.  Available under Version 2 of
the General Public License, Suricata eliminates the ID/PS engine cost
concerns while providing a scalable option for the most complex
network security architectures.


Multi-threading
---------------

As a multi-threaded engine, Suricata offers increased speed and
efficiency in network traffic analysis. In addition to hardware
acceleration (with hardware and network card limitations), the engine
is build to utilise the increased processing power offered by the
latest multi-core CPU chip sets. Suricata is developed for ease of
implementation and accompanied by a step-by-step getting started
documentation and user manual.

Development and features
------------------------
 
The goal of the Suricata Project Phase 1 was to have a distributable
and functional ID/PS engine.  The initial beta release was made
available for download on January 1, 2010.  The engine supports or
provides the following functionality: the latest Snort VRT, Snort
logging, rule language options, multi-threading, hardware acceleration
(with hardware and network card dependencies/limitations), unified
output enabling interaction with external log management systems,
IPv6, rule-based IP reputation, library plug-ability for interaction
with other applications, performance statistics output, and a simple
and effective getting started user manual.

By engaging the open source community and the leading ID/PS rule set
resources available, OISF has built the Suricata engine to simplify
the process of maintaining optimum security levels.  Through strategic
partnerships, OISF is leveraging the expertise of Emerging Threats
(www.emergingthreats.net) and other prominent resources in the
industry to provide the most current and comprehensive rule sets
available.

The HTP Library is an HTTP normaliser and parser written by Ivan
Ristic of Mod Security fame for the OISF. This integrates and provides
very advanced processing of HTTP streams for Suricata. The HTP library
is required by the engine, but may also be used independently in a
range of applications and tools.
