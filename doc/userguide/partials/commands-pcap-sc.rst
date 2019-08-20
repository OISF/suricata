.. Consider converting `.. description` to `.. option` when the
   minimum version of Sphinx on the primary distributions are all
   updated to generate duplicate reference links. For example, we
   can't use `.. option` on CentOS 7 which has Sphinx 1.1.3, but
   Fedora 30 with Sphinx 1.8.4 is fine.

.. describe:: pcap-file <file> <dir> [tenant] [continuous] [delete-when-done]

   Add pcap files to Suricata for sequential processing. The generated
   log/alert files will be put into the directory specified as second argument.
   Make sure to provide absolute path to the files and directory. It is
   acceptable to add multiple files without waiting the result.

.. describe:: pcap-file-continuous <file> <dir> [tenant] [delete-when-done]

   Add pcap files to Suricata for sequential processing. Directory will be
   monitored for new files being added until there is a use of
   **pcap-interrupt** or directory is moved or deleted.

.. describe:: pcap-file-number

   Number of pcap files waiting to get processed.

.. describe:: pcap-file-list

   List of queued pcap files.

.. describe:: pcap-last-processed

   Processed time of last file in milliseconds since epoch.

.. describe:: pcap-interrupt

   Terminate the current state by interrupting directory processing.

.. describe:: pcap-current

   Currently processed file.
