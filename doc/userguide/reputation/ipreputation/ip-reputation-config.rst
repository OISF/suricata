IP Reputation Config
====================

IP reputation has a few configuration directives, all disabled by default.


::


  # IP Reputation
  #reputation-categories-file: /etc/suricata/iprep/categories.txt
  #default-reputation-path: /etc/suricata/iprep
  #reputation-files:
  # - reputation.list

reputation-categories-file
~~~~~~~~~~~~~~~~~~~~~~~~~~

The categories file mapping numbered category values to short names.


::


  reputation-categories-file: /etc/suricata/iprep/categories.txt

default-reputation-path
~~~~~~~~~~~~~~~~~~~~~~~

Path where reputation files from the "reputation-files" directive are loaded from by default.


::


  default-reputation-path: /etc/suricata/iprep

reputation-files
~~~~~~~~~~~~~~~~

YAML list of file names to load. In case of a absolute path the file is loaded directly, otherwise the path from "default-reputation-path" is pre-pended to form the final path.


::


  reputation-files:
   - badhosts.list
   - knowngood.list
   - sharedhosting.list

Hosts
~~~~~

IP reputation information is stored in the host table, so the settings of the host table affect it.

Depending on the number of hosts reputation information is available for, the memcap and hash size may have to be increased.

Reloads
~~~~~~~

If the "rule-reloads" option is enabled, sending Suricata a USR2 signal will reload the IP reputation data, along with the normal rules reload.

During the reload the host table will be updated to contain the new data. The iprep information is versioned. When the reload is complete, Suricata will automatically clean up the old iprep information.

Only the reputation files will be reloaded, the categories file won't be. If categories change, Suricata should be restarted.

File format
~~~~~~~~~~~

The format of the reputation files is described in the :doc:`ip-reputation-format` page.
