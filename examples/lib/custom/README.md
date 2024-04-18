# Custom Library Example

This is an example of using the Suriata library with your own packets
and threads.

## Building In Tree

The Suricata build system has created a Makefile that should allow you
to build this application in-tree on most supported platforms. To
build simply run:

```
make
```

## Running

```
./custom -l . -- filename.pcap
```

For this example, any arguments before `--` are passed directly as
Suricata command line arguments. Arguments after the first `--` are
handled by this example program, and currently the only argument is a
PCAP filename to be read.

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
