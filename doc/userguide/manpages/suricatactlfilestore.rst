Suricata Control Filestore
==========================

SYNOPSIS
--------

**suricatactl filestore** [-h] <command> [<args>]

DESCRIPTION
-----------

**Filestore** allows to store files to disk if a particular signature is matched.

Syntax for usage in suricata.yaml:

**filestore:<direction>,<scope>;**

`direction` can be either of the following.

   1. request/to_server i.e. store a file in the request / to_server direction

   2. response/to_client i.e. store a file in the response / to_client direction

   3: both i.e. store both directions

`scope` can be either:

   1. `file` only store the matching file (for filename,fileext,filemagic matches)

   2. `tx` store all files from the matching HTTP transaction

   3. `ssn/flow` which means store all files from the TCP session/flow.

If direction and scope are omitted, the direction will be the same as the rule and the scope will be per file.

BUGS
----

Please visit Suricata's support page for information about submitting
bugs or feature requests.

NOTES
-----

* Suricata Home Page

    https://suricata-ids.org/

* Suricata Support Page

    https://suricata-ids.org/support/
