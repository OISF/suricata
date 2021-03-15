Tcmalloc
========

'tcmalloc' is a library Google created as part of the google-perftools
suite for improving memory handling in a threaded program. It's very
simple to use and does work fine with Suricata. It leads to minor
speed ups and also reduces memory usage quite a bit.

Installation
~~~~~~~~~~~~

On Ubuntu, install the libtcmalloc-minimal4 package:

::

  apt-get install libtcmalloc-minimal4

On Fedora, install the gperftools-libs package:

::

  yum install gperftools-libs

Usage
~~~~~

Use the tcmalloc by preloading it:

Ubuntu:

::

  LD_PRELOAD="/usr/lib/x86_64-linux-gnu/libtcmalloc_minimal.so.4" suricata -c suricata.yaml -i eth0

Fedora:

::

  LD_PRELOAD="/usr/lib64/libtcmalloc_minimal.so.4" suricata -c suricata.yaml -i eth0
