.. _File Extraction:

File Extraction
===============

Architecture
~~~~~~~~~~~~

The file extraction code works on top of selected protocol parsers (see supported protocols below). The application layer parsers run on top of the stream reassembly engine and the UDP flow tracking.

In case of HTTP, the parser takes care of dechunking and unzipping the request and/or response data if necessary.

This means that settings in the stream engine, reassembly engine and the application layer parsers all affect the workings of the file extraction.

The rule language controls which files are extracted and stored on disk.

Supported protocols are:

- HTTP
- SMTP
- FTP
- NFS
- SMB
- HTTP2

Settings
~~~~~~~~

*stream.checksum_validation* controls whether or not the stream engine rejects packets with invalid checksums. A good idea normally, but the network interface performs checksum offloading a lot of packets may seem to be broken. This setting is enabled by default, and can be disabled by setting to "no". Note that the checksum handling can be controlled per interface, see "checksum_checks" in example configuration.

*file-store.stream-depth* controls how far into a stream reassembly is done. Beyond this value no reassembly will be done. This means that after this value the HTTP session will no longer be tracked. By default a setting of 1 Megabyte is used. 0 sets it to unlimited. If set to no, it is disabled and stream.reassembly.depth is considered. Non-zero values must be greater than ``stream.stream-depth`` to be used.

*libhtp.default-config.request-body-limit* / *libhtp.server-config.<config>.request-body-limit* controls how much of the HTTP request body is tracked for inspection by the `http_client_body` keyword, but also used to limit file inspection. A value of 0 means unlimited.

*libhtp.default-config.response-body-limit* / *libhtp.server-config.<config>.response-body-limit* is like the request body limit, only it applies to the HTTP response body.


Output
~~~~~~

File-Store and Eve Fileinfo
---------------------------

There are two output modules for logging information about extracted files.
The first is ``eve.files`` which is an ``eve`` sub-logger
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

The ``file-store`` module uses its own log directory (default: `filestore` in
the default logging directory) and logs files using the SHA256 of the
contents as the filename. Each file is then placed in a directory
named `00` to `ff` where the directory shares the first 2 characters
of the filename. For example, if the SHA256 hex string of an extracted
file starts with "f9bc6d..." the file we be placed in the directory
`filestore/f9`.

The size of a file that can be stored depends on ``file-store.stream-depth``,
if this value is reached a file can be truncated and might not be stored completely.
If not enabled, ``stream.reassembly.depth`` will be considered.

Setting ``file-store.stream-depth`` to 0 permits store of the entire file;
here, 0 means "unlimited."

``file-store.stream-depth`` will always override ``stream.reassembly.depth``
when filestore keyword is used. However, it is not possible to set ``file-store.stream-depth``
to a value less than ``stream.reassembly.depth``. Values less than this amount are ignored
and a warning message will be displayed.

A protocol parser, like modbus, could permit to set a different
store-depth value and use it rather than ``file-store.stream-depth``.

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

These ``fileinfo`` records are identical to the ``fileinfo`` records
logged to the ``eve`` output.

See :ref:`suricata-yaml-file-store` for more information on
configuring the file-store output.

.. note:: This section documents version 2 of the ``file-store``. Version 1 of the file-store has been removed as of Suricata version 6.

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

Bundled with the Suricata download, is a file with more example rules. In the archive, go to the `rules` directory and check the ``files.rules`` file.


MD5
~~~

Suricata can calculate MD5 checksums of files on the fly and log them. See :doc:`md5` for an explanation on how to enable this.


.. toctree::

   md5
   public-sha1-md5-data-sets

Updating Filestore Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. toctree::

   config-update

File extraction over multiple flows
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Protocols such as HTTP and SMB allow to transfer a file using multiple flows.
For example in HTTP, this is done with the `Range` header in requests.

Suricata can manage to recombine the parts of files seen in the multiple flows
to run the logic on the reassembled file.

This is done using a hash table which has a timeout and a memory maximum capacity.
These can be configured in suricata.yaml in `app-layer.protocols.protocol.byterange` sections
where protocol can be http or smb.

The default memcap is 100 Mbytes and the default timeout is 60 seconds.