Multi Tenancy
=============

Introduction
------------

Multi tenancy support allows different tenants to use different
rule sets with different rule variables.

Tenants are identified by their `selector`; a `selector` can be
a VLAN (or VLAN tuple), interface/device, or from a pcap file (``direct``).

YAML
----

Add a new section in the main ("master") Suricata configuration file -- ``suricata.yaml`` -- named ``multi-detect``.

Settings:

* `enabled`: yes/no -> is multi-tenancy support enabled
* `selector`: direct (for unix socket pcap processing, see below), vlan, vlan-tuple or device
* `loaders`: number of `loader` threads, for parallel tenant loading at startup
* `tenants`: list of tenants
* `config-path`: path from where the tenant yamls are loaded

  * id: tenant id (numeric values only)
  * yaml: separate yaml file with the tenant specific settings

* `mappings`:

  * tenant-id: tenant to associate with the VLAN id, device or vlan-tuple.

Tenant mappings depend on the type of selector used:

* `vlan` or `device`

  * VLAN id or device: The outermost VLAN is used to match.

* `vlan-tuple`

  * VLAN tuple: Specify the VLAN identifiers -- outermost to innermost, e.g., `[3000, 1]` will match when the
    outermost VLAN id is 3000 and the innermost VLAN id is 1. The special value of `0` is a wildcard and "any VLAN in that position" will match.

.. note::
    Note that there must the same number of layers of VLAN encapsulation as there are values in the tuple for it to match.
    Additionally, Suricata supports 3 layers of VLAN ids: ``[outermost-id, middle-id, innermost-id]``

    * `[0, 302]` will match any packet with an innermost VLAN id of `302` on packets that are QinQ
    * `[3000, 0]` will match any packet with an outermost VLAN id of `3000` on packets that are QinQ
    * `[3000, 1000, 40]` will match any packet with 3-VLAN identifiers of outermost `3000`, middle `1000` and innermost `40`

::

  multi-detect:
    enabled: yes
    #selector: direct # direct, vlan, or vlan-tuple
    selector: vlan
    loaders: 3

    tenants:
    - id: 1
      yaml: tenant-1.yaml
    - id: 2
      yaml: tenant-2.yaml
    - id: 3
      yaml: tenant-3.yaml

    mappings:
    - vlan-id: 1000
      tenant-id: 1
    - vlan-id: 2000
      tenant-id: 2
    - vlan-id: 1112
      tenant-id: 3


This example uses the VLAN tuple selector for packets encapsulated with two VLAN ids:

::

  multi-detect:
    enabled: yes
    selector: vlan-tuple
    loaders: 3

    tenants:
    - id: 1
      yaml: tenant-1.yaml
    - id: 2
      yaml: tenant-2.yaml
    - id: 3
      yaml: tenant-3.yaml

    mappings:
    - vlan-tuple: [1000, 1001, 1002]
      tenant-id: 1
    - vlan-tuple: [2000, 2001, 2002]
      tenant-id: 2
    - vlan-tuple: [3000, 3001, 3002]
      tenant-id: 3


The tenant-1.yaml, tenant-2.yaml, tenant-3.yaml each contain a partial
configuration:

::

  # Set the default rule path here to search for the files.
  # if not set, it will look at the current working dir
  default-rule-path: /etc/suricata/rules
  rule-files:
    - rules1

  # You can specify a threshold config file by setting "threshold-file"
  # to the path of the threshold config file:
  # threshold-file: /etc/suricata/threshold.config

  classification-file: /etc/suricata/classification.config
  reference-config-file: /etc/suricata/reference.config

  # Holds variables that would be used by the engine.
  vars:

    # Holds the address group vars that would be passed in a Signature.
    # These would be retrieved during the Signature address parsing stage.
    address-groups:

      HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"

      EXTERNAL_NET: "!$HOME_NET"

      ...

    port-groups:

      HTTP_PORTS: "80"

      SHELLCODE_PORTS: "!80"

      ...

vlan-id
~~~~~~~

Assign tenants to VLAN ids. Suricata matches the outermost VLAN id with this value with
the selector ``vlan`` (default); the selector ``vlan-tuple`` should be used if QinQ is deployed and requires both
the inner and outer VLAN id values to match to determine the tenant.
Multiple VLANs can have the same tenant id. VLAN id values must be between 1 and 4094 with the ``vlan`` selector.
A wildcard value of ``00`` can be used with the ``vlan-tuple`` selector.

Example of VLAN mapping::

    mappings:
    - vlan-id: 1000
      tenant-id: 1
    - vlan-id: 2000
      tenant-id: 2
    - vlan-id: 1112
      tenant-id: 3

The mappings can also be modified over the unix socket, see below.

.. note::
   This can only be used if ``vlan.use-for-tracking`` is enabled.

vlan-tuple
~~~~~~~~~~

The ``vlan-tuple`` tag can only used with the ``vlan-tuple`` selector. The value will be used
to match with the innermost VLAN. Values of ``0`` will match any VLAN value.

Example of VLAN mapping::

    mappings:
    - vlan-tuple: [1000, 0]
      tenant-id: 1
    - vlan-tuple: [2000, 3000]
      tenant-id: 2
    - vlan-tuple: [1112, 3112]
      tenant-id: 3

The mappings can also be modified over the unix socket, see below.

.. note::
   This can only be used if ``vlan.use-for-tracking`` is enabled.

device
~~~~~~

Assign tenants to devices. A single tenant can be assigned to a device.
Multiple devices can have the same tenant id.

Example of device mapping::

    mappings:
    - device: ens5f0
      tenant-id: 1
    - device: ens5f1
      tenant-id: 3

The mappings are static and cannot be modified over the unix socket.

.. note::
 Not currently supported for IPS.

.. note::
 Support depends on a capture method using the 'livedev' API. Currently
 these are: pcap, AF_PACKET, PF_RING and Netmap.

Per tenant settings
-------------------

The following settings are per tenant:

* default-rule-path
* rule-files
* classification-file
* reference-config-file
* threshold-file
* address-vars
* port-vars

Unix Socket
-----------

Registration
~~~~~~~~~~~~

``register-tenant <id> <yaml>``

Examples:

::

  register-tenant 1 tenant-1.yaml
  register-tenant 2 tenant-2.yaml
  register-tenant 3 tenant-3.yaml
  register-tenant 5 tenant-5.yaml
  register-tenant 7 tenant-7.yaml

``unregister-tenant <id>``

::

  unregister-tenant 2
  unregister-tenant 1

Unix socket runmode (pcap processing)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Unix Socket ``pcap-file``  command is used to associate the tenant with
the pcap:

::

  pcap-file traffic1.pcap /logs1/ 1
  pcap-file traffic2.pcap /logs2/ 2
  pcap-file traffic3.pcap /logs3/ 3
  pcap-file traffic4.pcap /logs5/ 5
  pcap-file traffic5.pcap /logs7/ 7

This runs the traffic1.pcap against tenant 1 and it logs into /logs1/,
traffic2.pcap against tenant 2 and logs to /logs2/ and so on.

Live traffic mode
~~~~~~~~~~~~~~~~~

Multi-tenancy supports both VLAN and devices with live traffic.

In the master configuration yaml file, specify ``device``, ``vlan`` or ``vlan-tuple`` for the ``selector`` setting.

Registration
~~~~~~~~~~~~

Tenants can be mapped to vlan ids.


Examples using the ``vlan`` selector:

::

  register-tenant-handler <tenant id> vlan <vlan id>

::

  register-tenant-handler 1 vlan 1000

::

  unregister-tenant-handler <tenant id> vlan <vlan id>

::

  unregister-tenant-handler 4 vlan 1111
  unregister-tenant-handler 1 vlan 1000


Examples using the ``vlan-tuple`` selector:

::

  register-tenant-handler <tenant id> vlan-tuple <vlan outer id> [ <vlan inner id> [ <vlan innermost id>]]

::

  register-tenant-handler 1 vlan-tuple 1000 1001

::

  unregister-tenant-handler <tenant id> vlan-tuple <vlan outer id> [ <vlan inner id> [ <vlan innermost id>]]

::

  unregister-tenant-handler 4 vlan-tuple 1111 1
  unregister-tenant-handler 1 vlan-tuple 1000 2

The registration of tenant and tenant handlers can be done on a
running engine.

Reloads
~~~~~~~

Reloading all tenants:

``reload-tenants``

::

  reload-tenants

Reloading a single tenant:

``reload-tenant <tenant id> [yaml path]``

::

  reload-tenant 1 tenant-1.yaml
  reload-tenant 5

The ``[yaml path]`` is optional. If it isn't provided, the original path of
the tenant will be used during the reload.

Eve JSON output
---------------

When multi-tenant support is configured and the detect engine is active then
all EVE-types that report based on flows will also report the corresponding
``tenant_id`` for events matching a tenant configuration.
