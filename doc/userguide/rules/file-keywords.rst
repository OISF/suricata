.. _File Rule Keywords:

File Keywords
=============

Suricata comes with several rule keywords to match on various file
properties. They depend on properly configured
:doc:`../file-extraction/file-extraction`.

file.data
---------

The ``file.data`` sticky buffer matches on contents of files that are
seen in flows that Suricata evaluates. The various payload keywords can
be used (e.g. ``startswith``, ``nocase`` and ``bsize``) with ``file.data``.

Example::

  alert smtp any any -> any any (msg:"smtp app layer file.data example"; \
 file.data; content:"example file content"; sid:1; rev:1)

  alert http any any -> any any (msg:"http app layer file.data example"; \
 file.data; content:"example file content"; sid:2; rev:1)

  alert http2 any any -> any any (msg:"http2 app layer file.data example"; \
 file.data; content:"example file content"; sid:3; rev:1;)

  alert nfs any any -> any any (msg:"nfs app layer file.data example"; \
 file.data; content:" "; sid:5; rev:1)

  alert ftp-data any any -> any any (msg:"ftp app layer file.data example"; \
 file.data; content:"example file content"; sid:6; rev:1;)

  alert tcp any any -> any any (msg:"tcp file.data example"; \
 file.data; content:"example file content"; sid:4; rev:1)

**Note** file_data is the legacy notation but can still be used.


file.name
---------

``file.name`` is a sticky buffer that is used to look at filenames
that are seen in flows that Suricata evaluates. The various payload
keywords can be used (e.g. ``startswith``, ``nocase`` and ``bsize``)
with ``file.name``.

Example::

  file.name; content:"examplefilename";

``file.name`` supports multiple buffer matching, see :doc:`multi-buffer-matching`.

**Note** ``filename`` can still be used. A notable difference between
``file.name`` and ``filename`` is that ``filename`` assumes ``nocase``
by default. In the example below the two signatures are considered
the same.

Example::

  filename:"examplefilename";

  file.name; content:"examplefilename"; nocase;

fileext
--------

``fileext`` is used to look at individual file extensions that are
seen in flows that Suricata evaluates.

Example::

  fileext:"pdf";

**Note:** ``fileext`` does not allow partial matches. For example, if
a PDF file (.pdf) is seen by a Suricata signature with
fileext:"pd"; the signature will not produce an alert.

**Note:** ``fileext`` assumes ``nocase`` by default. This means
that a file with the extension .PDF will be seen the same as if
the file had an extension of .pdf.

**Note:** ``fileext`` and ``file.name`` can both be used to match on
file extensions. In the example below the two signatures are
considered the same.

Example::

  fileext:"pdf";

  file.name; content:".pdf"; nocase; endswith;

**Note**: While ``fileeext`` and ``file.name`` can both be used
to match on file extensions, ``file.name`` allows for partial
matching on file extensions. The following would match on a file
with the extension of .pd as well as .pdf.

Example::

  file.name; content:".pd";

file.magic
----------

Matches on the information libmagic returns about a file.

Example::

  file.magic; content:"executable for MS Windows";

**Note** ``filemagic`` can still be used. The only difference between
``file.magic`` and ``file.magic`` is that ``filemagic`` assumes ``nocase``
by default. In the example below the two signatures are considered
the same.

Example::

  filemagic:"executable for MS Windows";

  file.magic; content:"executable for MS Windows"; nocase;

Note: Suricata currently uses its underlying operating systems
version/implementation of libmagic. Different versions and
implementations of libmagic do not return the same information.
Additionally there are varying Suricata performance impacts
based on the version and implementation of libmagic.
Additional information about Suricata and libmagic can be found
here: https://redmine.openinfosecfoundation.org/issues/437

``file.magic`` supports multiple buffer matching, see :doc:`multi-buffer-matching`.

filestore
---------

Stores files to disk if the signature matched.

Syntax::

  filestore:<direction>,<scope>;

direction can be:

* request/to_server: store a file in the request / to_server direction
* response/to_client: store a file in the response / to_client direction
* both: store both directions

scope can be:

* file: only store the matching file (for filename,fileext,filemagic matches)
* tx: store all files from the matching HTTP transaction
* ssn/flow: store all files from the TCP session/flow.

If direction and scope are omitted, the direction will be the same as
the rule and the scope will be per file.

filemd5
-------

Match file :ref:`MD5 <md5>` against list of MD5 checksums.

Syntax::

  filemd5:[!]filename;

The filename is expanded to include the rule dir. In the default case
it will become /etc/suricata/rules/filename. Use the exclamation mark
to get a negated match. This allows for white listing.

Examples::

  filemd5:md5-blacklist;
  filemd5:!md5-whitelist;

*File format*

The file format is simple. It's a text file with a single md5 per
line, at the start of the line, in hex notation. If there is extra
info on the line it is ignored.

Output from md5sum is fine::

  2f8d0355f0032c3e6311c6408d7c2dc2  util-path.c
  b9cf5cf347a70e02fde975fc4e117760  util-pidfile.c
  02aaa6c3f4dbae65f5889eeb8f2bbb8d  util-pool.c
  dd5fc1ee7f2f96b5f12d1a854007a818  util-print.c

Just MD5's are good as well::

  2f8d0355f0032c3e6311c6408d7c2dc2
  b9cf5cf347a70e02fde975fc4e117760
  02aaa6c3f4dbae65f5889eeb8f2bbb8d
  dd5fc1ee7f2f96b5f12d1a854007a818

*Memory requirements*

Each MD5 uses 16 bytes of memory. 20 Million MD5's use about 310 MiB of memory.

See also: https://blog.inliniac.net/2012/06/09/suricata-md5-blacklisting/

filesha1
--------

Match file SHA1 against list of SHA1 checksums.

Syntax::

  filesha1:[!]filename;

The filename is expanded to include the rule dir. In the default case
it will become /etc/suricata/rules/filename. Use the exclamation mark
to get a negated match. This allows for white listing.

Examples::

  filesha1:sha1-blacklist;
  filesha1:!sha1-whitelist;

*File format*

Same as md5 file format.

filesha256
----------

Match file SHA256 against list of SHA256 checksums.

Syntax::

  filesha256:[!]filename;

The filename is expanded to include the rule dir. In the default case
it will become /etc/suricata/rules/filename. Use the exclamation mark
to get a negated match. This allows for white listing.

Examples::

  filesha256:sha256-blacklist;
  filesha256:!sha256-whitelist;

*File format*

Same as md5 file format.

filesize
--------

Match on the size of the file as it is being transferred.

filesize uses an :ref:`unsigned 64-bit integer <rules-integer-keywords>`.

Syntax::

  filesize:<value>;

Possible units are KB, MB and GB, without any unit the default is bytes.

Examples::

  filesize:100; # exactly 100 bytes
  filesize:100<>200; # greater than 100 and smaller than 200
  filesize:>100MB; # greater than 100 megabytes
  filesize:<100MB; # smaller than 100 megabytes

**Note**: For files that are not completely tracked because of packet
loss or stream.reassembly.depth being reached on the "greater than" is
checked. This is because Suricata can know a file is bigger than a
value (it has seen some of it already), but it can't know if the final
size would have been within a range, an exact value or smaller than a
value.

windows_pe
----------

The ``windows_pe`` keyword is used for detecting Windows Portable Executable (PE) files
in network traffic. PE files are the standard executable format for Windows operating
systems and include .exe, .dll, .sys and other executable file types.

**Structure of Windows PE Files**

A valid Windows PE file consists of:

1. **DOS Header**: Beginning with the "MZ" signature (0x4D 0x5A)
2. **DOS Stub**: Legacy DOS program
3. **PE Header**: Beginning with the "PE\\0\\0" signature (0x50 0x45 0x00 0x00)
4. **COFF Header**: Contains machine type, number of sections, and other metadata
5. **Optional Header**: Contains additional metadata about the executable
6. **Section Headers**: Describe the sections (.text, .data, .rsrc, etc.)
7. **Sections**: The actual code and data

**Syntax**::

  windows_pe: [architecture: <arch>][, size: <uint32>][, sections: <uint16>]...;

**Options**:

* ``architecture``: CPU architecture filter - ``x86``, ``x86_64``, ``arm``, ``arm64`` (optional, matches any if omitted)
* ``size``: Match SizeOfImage field (total mapped bytes) - uint32 with comparison operators
* ``sections``: Match NumberOfSections field (section count) - uint16 with comparison operators
* ``entry_point``: Match AddressOfEntryPoint RVA - uint32 with comparison operators
* ``subsystem``: Match PE subsystem type - uint16 value (2=GUI, 3=Console, 1=Native, etc.)
* ``characteristics``: Match COFF characteristics flags - uint16 hex value (0x0002=EXECUTABLE_IMAGE, 0x2000=DLL, etc.)
* ``dll_characteristics``: Match DLL characteristics/security flags - uint16 hex value (0x0040=ASLR/DYNAMIC_BASE, 0x0100=DEP/NX_COMPAT, etc.)

All numeric options support comparison operators: ``<``, ``>``, and range notation (e.g., ``1000<>5000``).

The keyword is typically used in conjunction with ``file.data`` and content matches to
detect PE file characteristics.

**Unified Keyword Syntax**

The ``windows_pe`` keyword consolidates all PE metadata filtering into a single comma-separated option list.
Options are specified as ``key: value`` pairs, all within the single keyword::

  windows_pe: architecture: x86_64, size: >1000000, sections: <8;

This unified approach consolidates all PE metadata filtering into a single keyword with multiple options.

**Examples**

Detect any Windows PE file download::

  alert http any any -> any any (msg:"Windows PE file detected"; \
      flow:established,to_client; \
      file.data; content:"MZ"; startswith; \
      windows_pe:; \
      sid:1; rev:1;)

Detect x86_64 PE files::

  alert http any any -> any any (msg:"x86_64 PE detected"; \
      flow:established,to_client; \
      file.data; content:"MZ"; startswith; \
      windows_pe: architecture: x86_64; \
      sid:2; rev:1;)

Detect PE file with specific size constraints::

  alert http any any -> any any (msg:"Medium-sized PE"; \
      flow:established,to_client; \
      file.data; content:"MZ"; startswith; \
      windows_pe: size: 100000<>500000; \
      sid:3; rev:1;)

Detect PE files with few sections (possibly packed)::

  alert http any any -> any any (msg:"Packed PE detected"; \
      flow:established,to_client; \
      file.data; content:"MZ"; startswith; \
      windows_pe: sections: <4; \
      sid:4; rev:1;)

Detect PE files with low entry point::

  alert http any any -> any any (msg:"Low entry point PE"; \
      flow:established,to_client; \
      file.data; content:"MZ"; startswith; \
      windows_pe: entry_point: <4096; \
      sid:5; rev:1;)

Detect PE files with subsystem::

  alert http any any -> any any (msg:"Console PE"; \
      flow:established,to_client; \
      file.data; content:"MZ"; startswith; \
      windows_pe: subsystem: 3; \
      sid:6; rev:1;)

Detect PE DLL files by characteristics::

  alert http any any -> any any (msg:"PE DLL download"; \
      flow:established,to_client; \
      file.data; content:"MZ"; startswith; \
      windows_pe: characteristics: 0x2002; \
      sid:7; rev:1;)

Detect PE files without ASLR::

  alert http any any -> any any (msg:"PE without ASLR"; \
      flow:established,to_client; \
      file.data; content:"MZ"; startswith; \
      windows_pe: dll_characteristics: <0x0040; \
      sid:8; rev:1;)

Combined metadata example (all constraints in one keyword)::

  alert http any any -> any any (msg:"Packed x64 PE"; \
      flow:established,to_client; \
      file.data; content:"MZ"; startswith; \
      windows_pe: architecture: x86_64, size: >100000, sections: <4, entry_point: <4096; \
      sid:9; rev:1;)

**Threat Hunting Examples**

Detect unsigned or tampered drivers::

  alert http any any -> any any (msg:"Unsigned driver detected"; \
      flow:established,to_client; \
      file.data; content:"MZ"; startswith; \
      windows_pe: architecture: x86_64, characteristics: 0x0002, subsystem: 1; \
      sid:100; rev:1;)

Detect potentially malicious x86 utilities (no DEP/NX support)::

  alert http any any -> any any (msg:"Suspicious x86 binary without DEP/NX"; \
      flow:established,to_client; \
      file.data; content:"MZ"; startswith; \
      windows_pe: architecture: x86, dll_characteristics: <0x0100; \
      sid:101; rev:1;)

Detect large DLLs (possible backdoor or trojan library)::

  alert http any any -> any any (msg:"Abnormally large DLL download"; \
      flow:established,to_client; \
      file.data; content:"MZ"; startswith; \
      windows_pe: characteristics: 0x2000, size: >50000000; \
      sid:102; rev:1;)

Detect uncommon ARM/ARM64 executables in HTTP traffic::

  alert http any any -> any any (msg:"ARM executable in HTTP traffic"; \
      flow:established,to_client; \
      file.data; content:"MZ"; startswith; \
      windows_pe: architecture: arm64; \
      sid:103; rev:1;)

Detect file with suspicious low entry point (code injection indicator)::

  alert http any any -> any any (msg:"PE with suspicious low entry point"; \
      flow:established,to_client; \
      file.data; content:"MZ"; startswith; \
      windows_pe: entry_point: <512; \
      sid:104; rev:1;)

Detect all x86_64 PE files with ASLR disabled::

  alert http any any -> any any (msg:"x86_64 PE without ASLR/DYNAMIC_BASE"; \
      flow:established,to_client; \
      file.data; content:"MZ"; startswith; \
      windows_pe: architecture: x86_64, dll_characteristics: <0x0040; \
      sid:105; rev:1;)

**Validation Requirements**

For a file to be considered a valid PE file, it must satisfy:

* **DOS Header Magic**: First 2 bytes must be "MZ" (0x4D 0x5A)
* **Minimum Size**: At least 64 bytes for the DOS header
* **PE Offset**: Valid offset at bytes 60-63 (little-endian) pointing to the PE signature
* **PE Signature**: "PE\\0\\0" (0x50 0x45 0x00 0x00) at the PE offset location
* **Reasonable Bounds**: PE offset must be within the file size and not exceed 0x10000

**Understanding PE Metadata in Logs**

When a PE file is detected, the following metadata fields are logged to eve.json for analysis:

* ``architecture`` - The machine type/CPU architecture as a hex string (e.g., ``"0x014c"`` for x86)
* ``architecture_name`` - Human-readable architecture name (e.g., ``"x86"``, ``"x86-64"``, ``"ARM"``, ``"ARM64"``, or ``"unknown"``)
* ``subsystem`` - Human-readable application subsystem name (e.g., ``"WINDOWS_GUI"``, ``"WINDOWS_CUI"``, ``"NATIVE"``)
* ``subsystem_id`` - Numeric subsystem value
* ``sections`` - Number of sections in the file
* ``characteristics`` and ``characteristics_names`` - COFF flags (EXECUTABLE_IMAGE, DLL, etc.)
* ``dll_characteristics`` and ``security_features`` - Security feature flags (ASLR, DEP/NX, Control Flow Guard, etc.)
* ``entry_point`` - AddressOfEntryPoint RVA
* ``size_of_image`` - Total mapped size
* ``pe_offset`` - Location of PE signature in file (typically 0x40; unusual values may indicate malformed or tampered files)

**Note on ``pe_offset` for Threat Hunting**: While logged, ``pe_offset`` has limited matching utility. Values outside the normal range (0x40-0x1000) are rare and primarily useful in forensic analysis of polyglot files or suspected packing. It is not recommended as a matching criterion in detection rules.

**Use Cases**

* **Malware Detection**: Identify potential malware executables in HTTP/SMTP/FTP traffic
* **Policy Enforcement**: Block executable downloads in corporate environments
* **Threat Hunting**: Track PE file transfers for forensic analysis
* **File Classification**: Categorize and log Windows executable traffic
* **Incident Response**: Detect lateral movement via executable transfers

**Performance Considerations**

* Use ``windows_pe`` with ``file.data`` buffer for optimal performance
* Combine with content matches to pre-filter data before PE validation
* Consider using ``filesize`` to avoid processing very large files
* Works best with proper file extraction configuration

**Supported Protocols**

The ``windows_pe`` keyword can be used with any protocol that supports file extraction:

* HTTP/HTTPS
* SMTP
* FTP
* SMB
* NFS

---

**Related Keywords**

* ``file.data`` - The buffer containing file data to inspect
* ``file.name`` - Match on the filename
* ``file.magic`` - Match on libmagic file type information
* ``filesize`` - Match on file size
* ``filestore`` - Store matched files to disk
* ``fileext`` - Match on file extension
* ``entropy`` - Analyze entropy of buffered data (can be used with executable metadata)
