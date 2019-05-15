# suricata-fuzzing
This project contains fuzz-targets for several interfaces and network protocols.  

## Preparation
To build the fuzz-targets the following requirement:
* suricata
* jansson 
* libnet 
* libyaml


## build and test
Steps for build and test the fuzz-targets using some scripts :
* create fuzz-envirorment with **docker**
* run **build.sh** to compile *suricata*
* run **patch.sh** to modify suricata.o
* run **make** to 
