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

**Note**: While``fileeext`` and ``file.name`` can both be used
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
