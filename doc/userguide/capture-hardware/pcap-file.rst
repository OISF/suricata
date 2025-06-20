.. _pcap_file:

PCAP File Reading
=================

Suricata offers a ``pcap-file`` capture method to process PCAP files and 
directories of PCAP files in an offline or live-feed manner.

Configuration
-------------

.. code-block:: yaml

  pcap-file:
    checksum-checks: auto
    # tenant-id: none
    # delete-when-done: false
    # recursive: false
    # continuous: false
    # delay: 30
    # poll-interval: 5

Directory-related options
-------------------------

The **recursive** option enables Suricata to traverse subdirectories within 
the specified directory, up to a maximum depth of 255. This allows for 
processing of PCAP files located in nested folders. Note that the recursive 
option cannot be used together with the ``continuous`` option. 
The command-line option is
:ref:`--pcap-file-recursive <cmdline-option-pcap-file-recursive>`.

The **continuous** option allows Suricata to monitor the specified directory
for new files, processing them as they appear.
This is useful for live environments where new PCAP files are continuously
added. The continuous option cannot be combined with the ``recursive`` option.
The command-line option is
:ref:`--pcap-file-continuous <cmdline-option-pcap-file-continuous>`..

The **delay** option specifies the amount of time, in seconds,
that Suricata waits before processing newly detected files.
This helps prevent the processing of incomplete files that are still
being written. The delay option is applicable with
the ``continuous`` mode.

The **poll-interval** option determines how frequently, in seconds,
Suricata checks the directory for new files. Adjusting this interval
can help balance responsiveness and resource usage.

.. note::

  ``continuous`` and ``recursive`` cannot be enabled simultaneously.

.. note::
  
  Symlinks are ignored during recursive traversal.


Other options
-------------

**checksum-checks**

- **auto** (default): Suricata detects checksum offloading statistically.
- **yes**: Forces checksum validation.
- **no**: Disables checksum validation.
- The command-line option is :ref:`-k <cmdline-option-k>`

**tenant-id**

- Specifies the tenant for multi-tenant setups with direct select.
- The PCAP is processed by the detection engine assigned to the specified
  tenant.

**delete-when-done**

- If ``true``, Suricata deletes the PCAP file after processing.
- The command-line option is
  :ref:`--pcap-file-delete <cmdline-option-pcap-file-delete>`

**BPF filter**

- Suricata supports BPF filters for packet capture that is also applicable
  to the ``pcap-file`` capture method.
- The BPF filter is specified in the file with the :ref:`-F <cmdline-option-F>`
  command-line option.
