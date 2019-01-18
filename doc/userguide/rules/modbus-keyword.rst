Modbus Keyword
==============

The modbus keyword can be used for matching on various properties of
Modbus requests.

There are three ways of using this keyword:

* matching on functions properties with the setting "function";
* matching on directly on data access with the setting "access";
* matching on unit identifier with the setting "unit" only or with the previous setting "function" or "access".

With the setting **function**, you can match on:

* an action based on a function code field and a sub-function code when applicable;
* one of three categories of Modbus functions;
* public functions that are publicly defined (setting "public")
* user-defined functions (setting "user")
* reserved functions that are dedicated to proprietary extensions of Modbus (keyword "reserved")
* one of the two sub-groups of public functions:

  * assigned functions whose definition is already given in the Modbus specification (keyword "assigned");
  * unassigned functions, which are reserved for future use (keyword "unassigned").

Syntax::

  modbus: function <value>
  modbus: function <value>, subfunction <value>
  modbus: function [!] <assigned | unassigned | public | user | reserved | all>

Sign '!' is negation

Examples::

  modbus: function 21                # Write File record function
  modbus: function 4, subfunction 4  # Force Listen Only Mode (Diagnostics) function
  modbus: function assigned          # defined by Modbus Application Protocol Specification V1.1b3
  modbus: function public            # validated by the Modbus.org community
  modbus: function user              # internal use and not supported by the specification
  modbus: function reserved          # used by some companies for legacy products and not available for public use
  modbus: function !reserved         # every function but reserved function

With the **access** setting, you can match on:

* a type of data access (read or write);
* one of primary tables access (Discretes Input, Coils, Input Registers and Holding Registers);
* a range of addresses access;
* a written value.

Syntax::

  modbus: access <read | write>
  modbus: access read <discretes | coils | input | holding>
  modbus: access read <discretes | coils | input | holding>, address <value>
  modbus: access write < coils | holding>
  modbus: access write < coils | holding>, address <value>
  modbus: access write < coils | holding>, address <value>, value <value>

With _<value>_ setting matches on the address or value as it is being
accessed or written as follows::

  address 100      # exactly address 100
  address 100<>200 # greater than address 100 and smaller than address 200
  address >100     # greater than address 100
  address <100     # smaller than address 100

Examples::

  modbus: access read                                    # Read access
  modbus: access write                                   # Write access
  modbus: access read input                              # Read access to Discretes Input table
  modbus: access write coils                             # Write access to Coils table
  modbus: access read discretes, address <100            # Read access at address smaller than 100 of Discretes Input table
  modbus: access write holding, address 500, value >200  # Write value greater than 200 at address 500 of Holding Registers table

With the setting **unit**, you can match on:

* a MODBUS slave address of a remote device connected on the sub-network behind a bridge or a gateway. The destination IP address identifies the bridge itself and the bridge uses the MODBUS unit identifier to forward the request to the right slave device.

Syntax::

  modbus: unit <value>
  modbus: unit <value>, function <value>
  modbus: unit <value>, function <value>, subfunction <value>
  modbus: unit <value>, function [!] <assigned | unassigned | public | user | reserved | all>
  modbus: unit <value>, access <read | write>
  modbus: unit <value>, access read <discretes | coils | input | holding>
  modbus: unit <value>, access read <discretes | coils | input | holding>, address <value>
  modbus: unit <value>, access write < coils | holding>
  modbus: unit <value>, access write < coils | holding>, address <value>
  modbus: unit <value>, access write < coils | holding>, address <value>, value <value>

With _<value>_ setting matches on the address or value as it is being
accessed or written as follows::

  unit 10     # exactly unit identifier 10
  unit 10<>20 # greater than unit identifier 10 and smaller than unit identifier 20
  unit >10    # greater than unit identifier 10
  unit <10    # smaller than unit identifier 10

Examples::

  modbus: unit 10                                                       # Unit identifier 10
  modbus: unit 10, function 21                                          # Unit identifier 10 and write File record function
  modbus: unit 10, function 4, subfunction 4                            # Unit identifier 10 and force Listen Only Mode (Diagnostics) function
  modbus: unit 10, function assigned                                    # Unit identifier 10 and assigned function
  modbus: unit 10, function !reserved                                   # Unit identifier 10 and every function but reserved function
  modbus: unit 10, access read                                          # Unit identifier 10 and Read access
  modbus: unit 10, access write coils                                   # Unit identifier 10 and Write access to Coils table
  modbus: unit >10, access read discretes, address <100                 # Greater than unit identifier 10 and Read access at address smaller than 100 of Discretes Input table
  modbus: unit 10<>20, access write holding, address 500, value >200    # Greater than unit identifier 10 and smaller than unit identifier 20 and Write value greater than 200 at address 500 of Holding Registers table

(cf. http://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf)

**Note:** Address of read and write are starting at 1. So if your system
is using a start at 0, you need to add 1 the address values.

**Note:** According to MODBUS Messaging on TCP/IP Implementation Guide
V1.0b, it is recommended to keep the TCP connection opened with a
remote device and not to open and close it for each MODBUS/TCP
transaction. In that case, it is important to set the depth of the
stream reassembling as unlimited (stream.reassembly.depth: 0)

**Note:** According to MODBUS Messaging on TCP/IP Implementation Guide
V1.0b, the MODBUS slave device addresses on serial line are assigned from 1 to
247 (decimal). Address 0 is used as broadcast address.

(cf. http://www.modbus.org/docs/Modbus_Messaging_Implementation_Guide_V1_0b.pdf)

Paper and presentation (in french) on Modbus support are available :
http://www.ssi.gouv.fr/agence/publication/detection-dintrusion-dans-les-systemes-industriels-suricata-et-le-cas-modbus/
