File Extraction
===============

Architecture
~~~~~~~~~~~~

The file extraction code works on top of the HTTP and SMTP parsers. The HTTP parser takes care of dechunking and unzipping the request and/or response data if necessary. The HTTP/SMTP parsers runs on top of the stream reassembly engine.

This means that settings in the stream engine, reassembly engine and the HTTP parser all affect the workings of the file extraction.

What files are actually extracted and stored to disk is controlled by the rule language.


Settings
~~~~~~~~

*stream.checksum_validation* controls whether or not the stream engine rejects packets with invalid checksums. A good idea normally, but the network interface performs checksum offloading a lot of packets may seem to be broken. This setting is enabled by default, and can be disabled by setting to "no". Note that the checksum handling can be controlled per interface, see "checksum_checks" in example configuration.

*file-store.stream-depth* controls how far into a stream reassembly is done. Beyond this value no reassembly will be done. This means that after this value the HTTP session will no longer be tracked. By default a settings of 1 Megabyte is used. 0 sets it to unlimited. If set to no, it is disabled and stream.reassembly.depth is considered.

*libhtp.default-config.request-body-limit* / *libhtp.server-config.<config>.request-body-limit* controls how much of the HTTP request body is tracked for inspection by the http_client_body keyword, but also used to limit file inspection. A value of 0 means unlimited.

*libhtp.default-config.response-body-limit* / *libhtp.server-config.<config>.response-body-limit* is like the request body limit, only it applies to the HTTP response body.


Output
~~~~~~

For file extraction two separate output modules were created:
"file-log" and "file-store". They need to be enabled in the
:doc:`../configuration/suricata-yaml`. For "file-store", the "files"
drop dir must be configured.


::


  - file-store:
      enabled: yes      # set to yes to enable
      log-dir: files    # directory to store the files
      force-magic: no   # force logging magic on all stored files
      force-md5: no     # force logging of md5 checksums
      stream-depth: 1mb # reassemble 1mb into a stream, set to no to disable
      waldo: file.waldo # waldo file to store the file_id across runs
      max-open-files: 0 # how many files to keep open (O means none)
      write-meta: yes   # write a .meta file if set to yes

Each file that is stored with have a name "file.<id>". The id will be reset and files will be overwritten unless the waldo option is used. A "file.<id>.meta" file is generated containing file metadata if write-meta is set to yes (default).


::


    - file-log:
        enabled: yes
        filename: files-json.log
        append: yes
        #filetype: regular # 'regular', 'unix_stream' or 'unix_dgram'
        force-magic: no   # force logging magic on all logged files
        force-md5: no     # force logging of md5 checksums


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

Bundled with the Suricata download is a file with more example rules. In the archive, go to the rules/ directory and check the files.rules file.

MD5
~~~

Suricata can calculate MD5 checksums of files on the fly and log them. See :doc:`md5` for an explanation on how to enable this.


.. toctree::

   md5
   public-sha1-md5-data-sets
