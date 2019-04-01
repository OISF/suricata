.. option:: pcap-file <file> <dir> [tenant] [continuous] [delete-when-done]

   Add pcap files to Suricata for sequential processing. The generated
   log/alert files will be put into the directory specified as second argument.
   Make sure to provide absolute path to the files and directory. It is
   acceptable to add multiple files without waiting the result.

.. option:: pcap-file-continuous <file> <dir> [tenant] [delete-when-done]

   Add pcap files to Suricata for sequential processing. Directory will be
   monitored for new files being added until there is a use of
   **pcap-interrupt** or directory is moved or deleted.

.. option:: pcap-file-number

   Number of pcap files waiting to get processed.

.. option:: pcap-file-list

   List of queued pcap files.

.. option:: pcap-last-processed

   Processed time of last file in milliseconds since epoch.

.. option:: pcap-interrupt

   Terminate the current state by interrupting directory processing.

.. option:: pcap-current

   Currently processed file.
