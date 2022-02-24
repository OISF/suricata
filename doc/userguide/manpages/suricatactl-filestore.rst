Suricata Control Filestore
==========================

SYNOPSIS
--------

**suricatactl filestore** [-h] <command> [<args>]

DESCRIPTION
-----------

This command lets you perform certain operations on Suricata filestore.


OPTIONS
--------

.. Basic options

.. option:: -h

Get help about the available commands.


COMMANDS
---------

**prune [-h|--help] [-n|--dry-run] [-v|verbose] [-q|--quiet] -d <DIRECTORY>
--age <AGE>**

Prune files older than a given age.

-d <DIRECTORY> | --directory <DIRECTORY> is a required argument which tells
that user must provide the suricata filestore directory on which all the
specified operations are to be performed.

--age <AGE> is a required argument asking the age of the files. Files older
than the age mentioned with this option shall be pruned.

-h | --help is an optional argument with which you can ask for help about the
command usage.

-n | --dry-run is an optional argument which makes the utility print only what
would happen

-v | --verbose is an optional argument to increase the verbosity of command.

-q | --quiet is an optional argument that helps log errors and warnings only
and keep silent about everything else.


BUGS
----

Please visit Suricata's support page for information about submitting
bugs or feature requests.

NOTES
-----

* Suricata Home Page

    https://suricata.io/

* Suricata Support Page

    https://suricata.io/support/
