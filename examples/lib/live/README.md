# Live Capture Library Example

This is an example of using the Suricata library to capture live
traffic from a network interface with custom packet handling and
threading.

## Building In Tree

The Suricata build system has created a Makefile that should allow you
to build this application in-tree on most supported platforms. To
build simply run:

```
make
```

## Running

```
./live -i eth0 -l .
```

This example requires at least one `-i` option to specify the network
interface to capture from. You can specify multiple interfaces to
capture from multiple sources simultaneously - a separate worker thread
will be created for each interface:

```
./live -i eth0 -i eth1
```

Any additional arguments are passed directly to Suricata as command
line arguments.

Example with common options:
```
sudo ./live -i eth0 -- -l . -S rules.rules
```

Example capturing from multiple interfaces:
```
sudo ./live -i eth0 -i wlan0 -- -l . -S rules.rules
```

Shutdown: each worker thread may call EngineStop when its capture ends; the
main loop waits for this signal, performs SuricataShutdown concurrently with
per-thread SCTmThreadsSlotPacketLoopFinish, then joins all worker threads
before GlobalsDestroy.

The example supports up to 16 interfaces simultaneously.

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
