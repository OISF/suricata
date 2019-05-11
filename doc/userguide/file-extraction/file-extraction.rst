File Extraction
===============

Architecture
~~~~~~~~~~~~

The file extraction code works on top of the some protocols parsers. The application layer parsers runs on top of the stream reassembly engine and the UDP flow tracking.

In case of HTTP, the parser takes care of dechunking and unzipping the request and/or response data if necessary.

This means that settings in the stream engine, reassembly engine and the application layer parsers all affect the workings of the file extraction.

What files are actually extracted and stored to disk is controlled by the rule language.

Supported protocols are:

- HTTP
- SMTP
- FTP
- NFS
- SMB

Settings
~~~~~~~~

*stream.checksum_validation* controls whether or not the stream engine rejects packets with invalid checksums. A good idea normally, but the network interface performs checksum offloading a lot of packets may seem to be broken. This setting is enabled by default, and can be disabled by setting to "no". Note that the checksum handling can be controlled per interface, see "checksum_checks" in example configuration.

*file-store.stream-depth* controls how far into a stream reassembly is done. Beyond this value no reassembly will be done. This means that after this value the HTTP session will no longer be tracked. By default a settings of 1 Megabyte is used. 0 sets it to unlimited. If set to no, it is disabled and stream.reassembly.depth is considered.

*libhtp.default-config.request-body-limit* / *libhtp.server-config.<config>.request-body-limit* controls how much of the HTTP request body is tracked for inspection by the http_client_body keyword, but also used to limit file inspection. A value of 0 means unlimited.

*libhtp.default-config.response-body-limit* / *libhtp.server-config.<config>.response-body-limit* is like the request body limit, only it applies to the HTTP response body.


Output
~~~~~~

File-Store and Eve Fileinfo
---------------------------

There are two output modules for logging information about files
extracted. The first is ``eve.files`` which is an ``eve`` sub-logger
that logs ``fileinfo`` records. These ``fileinfo`` records provide
metadata about the file, but not the actual file contents.

This must be enabled in the ``eve`` output::

  - outputs:
      - eve-log:
          types:
	    - files:
	        force-magic: no
	        force-hash: [md5,sha256]

See :ref:`suricata-yaml-outputs-eve` for more details on working
with the `eve` output.

The other output module, ``file-store`` stores the actual files to
disk.

The ``file-store`` uses its own log directory (default: `filestore` in
the default logging directory) and logs files using the SHA256 of the
contents as the filename. Each file is then placed in a directory
named `00` to `ff` where the directory shares the first 2 characters
of the filename. For example, if the SHA256 hex string of an extracted
file starts with "f9bc6d..." the file we be placed in the directory
`filestore/f9`.

Using the SHA256 for file names allows for automatic de-duplication of
extracted files. However, the timestamp of a pre-existing file will be
updated if the same files is extracted again, similar to the `touch`
command.

Optionally a ``fileinfo`` record can be written to its own file
sharing the same SHA256 as the file it references. To handle recording
the metadata of each occurrence of an extracted file, these filenames
include some extra fields to ensure uniqueness. Currently the format
is::

  <SHA256>.<SECONDS>.<ID>.json

where ``<SECONDS>`` is the seconds from the packet that triggered the
stored file to be closed and ``<ID>`` is a unique ID for the runtime
of the Suricata instance. These values should not be depended on, and
are simply used to ensure uniqueness.

These ``fileinfo`` records are idential to the ``fileinfo`` records
logged to the ``eve`` output.

See :ref:`suricata-yaml-file-store` for more information on
configuring the file-store output.

.. note:: This section documents version 2 of the ``file-store``.

File-Store (Version 1)
----------------------

File-store version 1 has been replaced by version 2 and is no longer
recommended.

::

  - file-store:
      enabled: yes      # set to yes to enable
      log-dir: files    # directory to store the files
      force-magic: no   # force logging magic on all stored files
      force-hash: [md5] # force logging of md5 checksums
      stream-depth: 1mb # reassemble 1mb into a stream, set to no to disable
      waldo: file.waldo # waldo file to store the file_id across runs
      max-open-files: 0 # how many files to keep open (O means none)
      write-meta: yes   # write a .meta file if set to yes
      include-pid: yes  # include the pid in filenames if set to yes.

Each file that is stored will have a name "file.<id>". The id will be reset and files will be overwritten unless the waldo option is used. A "file.<id>.meta" file is generated containing file metadata if write-meta is set to yes (default). If the include-pid option is set, the files will instead have a name "file.<pid>.<id>", and metafiles will be "file.<pid>.<id>.meta". Files will additionally have the suffix ".tmp" while they are open, which is only removed when they are finalized.

Rules
~~~~~

Without rules in place no extraction will happen. The simplest rule would be:


::


  alert http any any -> any any (msg:"FILE store all"; filestore; sid:1; rev:1;)

This will simply store all files to disk.

Want to store all files with a pdf extension?


::


  alert http any any -> any any (msg:"FILE PDF file claimed"; fileext:"pdf"; filestore; sid:2; rev:1;)

Or rather all actual pdf files?


::


  alert http any any -> any any (msg:"FILE pdf detected"; filemagic:"PDF document"; filestore; sid:3; rev:1;)

Or rather only store files from black list checksum md5 ?


::


  alert http any any -> any any (msg:"Black list checksum match and extract MD5"; filemd5:fileextraction-chksum.list; filestore; sid:4; rev:1;)

Or only store files from black list checksum sha1 ?


::


  alert http any any -> any any (msg:"Black list checksum match and extract SHA1"; filesha1:fileextraction-chksum.list; filestore; sid:5; rev:1;)

Or finally store files from black list checksum sha256 ?


::


  alert http any any -> any any (msg:"Black list checksum match and extract SHA256"; filesha256:fileextraction-chksum.list; filestore; sid:6; rev:1;)

Bundled with the Suricata download is a file with more example rules. In the archive, go to the rules/ directory and check the files.rules file.


MD5
~~~

Suricata can calculate MD5 checksums of files on the fly and log them. See :doc:`md5` for an explanation on how to enable this.


.. toctree::

   md5
   public-sha1-md5-data-sets
