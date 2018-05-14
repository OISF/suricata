Yara Keyword
============

The ``yara`` keyword depends on properly configured
:doc:`../file-extraction/file-extraction`.

yara
----

Match a file against a YARA-rule.

Syntax::

  yara:[!]<yarafilename>;

Examples::

  yara:malware.yara;
  yara:"malware.yarac";
  yarac:!proprietary.yarac;

The double quotation marks are optional.

The ``yarac`` keyword is an alias for ``yara``.

Example rule::

  alert http any any -> any any (yara:malware.yarac; sid:1;)

Example rule to detect and store new malware samples::

  alert http any any <> any any (filemd5:!known-malware; yara:malware.yarac; filestore; sid:1;)

**Note**: Passing pre-compiled YARA-rules will reduce the startup and
rule reload time. YARA-rules can be compiled with the ``yarac`` tool
from the YARA project (https://virustotal.github.io/yara/).

The YARA filename will be appended to the default rule location.

Matching options for YARA can be configured
in the :ref:`yara configuration section<yara>`.
