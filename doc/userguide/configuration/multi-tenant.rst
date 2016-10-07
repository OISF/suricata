Multi Tenancy
=============

Introduction
------------

Multi tenancy support allows for different rule sets with different
rule vars.

YAML
----

In the main ("master") YAML, the suricata.yaml, a new section called
"multi-detect" should be added.

Settings:

* enabled: yes/no -> is multi-tenancy support enable
* default: yes/no -> is the normal detect config a default 'fall back' tenant?
* selector: direct (for unix socket pcap processing, see below) or vlan
* loaders: number of 'loader' threads, for parallel tenant loading at startup
* tenants: list of tenants

  * id: tenant id
  * yaml: separate yaml file with the tenant specific settings

* mappings:

  * vlan id
  * tenant id: tenant to associate with the vlan id

::

  multi-detect:
    enabled: yes
    #selector: direct # direct or vlan
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

Unix Socket
-----------

Registration
~~~~~~~~~~~~

register-tenant <id> <yaml>

Examples:

::

  register-tenant 1 tenant-1.yaml
  register-tenant 2 tenant-2.yaml
  register-tenant 3 tenant-3.yaml
  register-tenant 5 tenant-5.yaml
  register-tenant 7 tenant-7.yaml

unregister-tenant <id>

::

  unregister-tenant 2
  unregister-tenant 1

Unix socket runmode (pcap processing)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Unix Socket "pcap-file" command can be used to select the tenant
to inspect the pcap against:

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

For live traffic currently only a vlan based multi-tenancy is supported.

The master yaml needs to have the selector set to "vlan".

Registration
~~~~~~~~~~~~

Tenants can be mapped to vlan id's.

register-tenant-handler <tenant id> vlan <vlan id>

::

  register-tenant-handler 1 vlan 1000

unregister-tenant-handler <tenant id> vlan <vlan id>

::

  unregister-tenant-handler 4 vlan 1111
  unregister-tenant-handler 1 vlan 1000

The registration of tenant and tenant handlers can be done on a
running engine.
