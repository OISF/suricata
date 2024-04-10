# LibCapture Example

This is an example of using the Suricata library with the "lib"
capture method. The "lib" capture method is a simpler way of providing
packets to Suricata if you need to drive the deliver of packets,
rather than having Suricata run the main loop.

## Building In Tree

The Suricata build system has created a Makefile that should allow you
to build this application in-tree on most supported platforms. To
build simply run:

```
make
```

## Building Out of Tree

A Makefile.example has also been generated to use as an example on how
to build against the library in a standalone application.

First build and install the Suricata library including:

```
make install-library
make install-headers
```

Then run:

```
make -f Makefile.example
```

If you installed to a non-standard location, you need to ensure that
`libsuricata-config` is in your path, for example:

```
PATH=/opt/suricata/bin:$PATH make -f Makefile.example
```
