Symantec SSL Visibility (BlueCoat)
==================================

As Suricata itself cannot decrypt SSL/TLS traffic, some organizations use
a decryption product to handle this. This document will offer some advice
on using Suricata with the Symantec SSL Visibility appliance (formerly
known as BlueCoat).


Appliance Software Version
--------------------------

The appliance comes with two major software version options. The 3.x and 4.x
series. Suricata works best with the 4.x series.

TLS1.3 is only properly supported in the 4.x version of the appliance
software.


Magic Markers
-------------

The appliance has an indicator that data is decrypted. This is done using
a special magic source MAC address, or using a special VLAN header. Since
Suricata can use VLANs as part of flow tracking, it is recommended to use
the source MAC method.

In the 3.x version of the software these markers are always there, the
config just allows setting which type will be used. In the 4.x software the
markers are optional.


TCP handling
------------

In the 3.x software, a bit of care is required in TCP stream reassembly
handling in Suricata. The decrypted traffic is presented to the IDS as
TCP data packets, that are not ack'd as regularly as would be expected
in a regular TCP session. A large TCP window is used to not violate the
TCP specs. Since in IDS mode Suricata waits for ACKs for much of its
processing, this can lead to delays in detection and logging, as well
as increased resource usage due to increased data buffering.

To avoid this, enable the 'stream.inline' mode, which processed data
segments as they come in without waiting for the ACKs.

The 4.x software sends more regular ACKs and does not need any special
handling on the Suricata side.


TLS matching in Suricata
------------------------

The appliance takes care of the TLS handling and decryption, presenting
only the decrypted data to Suricata. This means that Suricata will not
see the TLS handshake. As a consequence of this, Suricata cannot inspect
the TLS handshake or otherwise process it. This means that for decrypted
TLS sessions, Suricata will not do any TLS keyword inspection (such as
fingerprint matching and ja3), TLS logging or TLS certificate extraction.

If it is important to match on and/or log such information as well, the
appliance facilities for matching and logging themselves will have to be
used.

For TLS traffic where the appliance security policy does not lead to
decryption of the traffic, the TLS handshake is presented to Suricata
for analysis and logging.

IPS
---

When using Suricata in IPS mode with the appliance, some things will
have to be considered:

* if Suricata DROPs a packet in the decrypted traffic, this will be seen
  by the appliance after which it will trigger a RST session teardown.

* if a packet takes more than one second to process, it will automatically
  be considered a DROP by the appliance. This should not happen in normal
  traffic, but with very inefficient Lua scripts this could perhaps
  happen. The appliance can also be configured to wait for 5 seconds.

* When using the Suricata 'replace' keyword to modify data, be aware
  that the 3.x appliance software will not pass the modification on to
  the destination so this will not have any effect. The 4.x appliance
  software does support passing on modifications that were made to the
  unencrypted text, by default this feature is disabled but you can
  enable it if you want modifications to be passed on to the destination
  in the re-encrypted stream. Due to how Suricata works, the size of
  the payloads cannot be changed.
