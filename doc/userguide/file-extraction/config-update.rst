.. _filestore-update-v1-to-v2:

Update File-store v1 Configuration to V2
========================================

Given a file-store configuration like::

  - file-store:
      enabled: yes        # set to yes to enable
      log-dir: files      # directory to store the files
      force-magic: no     # force logging magic on all stored files
      force-hash: [md5]   # force logging of md5 checksums
      force-filestore: no # force storing of all files
      stream-depth: 1mb   # reassemble 1mb into a stream, set to no to disable
      waldo: file.waldo   # waldo file to store the file_id across runs
      max-open-files: 0   # how many files to keep open (O means none)
      write-meta: yes     # write a .meta file if set to yes
      include-pid: yes    # include the pid in filenames if set to yes.

The following changes will need to be made to convert to a v2 style configuration:

* The ``version`` field must be set to 2.
* The ``log-dir`` field should be renamed to ``dir``. It is recommended to use a new directory instead of an existing v1 directory.
* Remove the ``waldo`` option. It is no longer used.
* Remove the ``write-meta`` option.
* Optionally set ``write-fileinfo`` to enable writing of a metadata file along side the extracted file. Not that this option is disabled by default as a ``fileinfo`` event can be written to the Eve log file.
* Remove the ``include-pid`` option. There is no equivalent to this option in file-store v2.

Example converted configuration::

  - file-store:
      version: 2
      enabled: yes
      dir: filestore
      force-hash: [md5]
      file-filestore: no
      stream-depth: 1mb
      max-open-files: 0
      write-fileinfo: yes

Refer to the :ref:`File Extraction` section of the manual for information about the format of the file-store directory for file-store v2.
