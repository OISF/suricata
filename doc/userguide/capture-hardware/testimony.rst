Testimony
=========

Testimony is a single-machine, multi-process architecture for sharing AF_PACKET data across processes. This allows packets to be copied from NICs into memory a single time. Then, multiple processes can process this packet data in parallel without the need for additional copies.

Testimony allows users to configure multiple different AF_PACKET sockets with different filters, blocks, etc. Administrators can specify BPF filters for these sockets, as well as which user should have access to which socket. This allows admins to easily set up access to a restricted set of packets for specific users.

Use case:
----------

Testimony is an effective and easily configurable tool for running a few IDS tools on one host at the same time. 
For example, Suricata, Zeek, and custom packet logging tool should work on one host effectively.
For this purpose, Suricata can be configured to use testimony socket as a packet source, zeek-testimony-plugin https://packages.zeek.org/packages/view/1c9e42ea-8b61-11ea-9321-0a645a3f3086 can be used for Zeek and testimony client can be used as packet logging tool. 

Compiling Suricata
------------------

Testimony can be pulled from github https://github.com/google/testimony.
Libtestimony source code is located in 'c' folder.
All needed dependencies could be installed with command::

    make -C c install 

When Testimony libraries and include files are installed, add ``--enable-testimony`` to the configure line.
If the includes or libraries are not added to a standard location, the location can
be specified on the Suricata configure commandline.

Example::

    ./configure --enable-testimony --with-testimony-includes=/usr/include  --with-testimony-libraries=/usr/lib

Starting Suricata
-----------------

Suricata can be started this way to use testimony socket:

::

    suricata --testimony=<socket>
    suricata --testimony=/tmp/testimony.sock

In the above example Suricata will start reading from /tmp/testimony.sock. The number of
created threads depends on the fanout size (number of memory blocks which packets are balanced between) which is configured in testimony and suricata configuration files.

suricata.yaml::

    testimony:
      - socket: /tmp/testimony.sock
        fanout-size: 4

/etc/testimony.conf::
    
    [{  "SocketName": "/tmp/testimony.sock",
        "Interface": "eth0",
        "BlockSize": 1048576,
        "NumBlocks": 16,
        "FanoutSize": 4,
        "BlockTimeoutMillis": 1000,
        "User": "root"}]

Testimony Configuration
~~~~~~~~~~~~~~~~~~~~~~~
Configuration above has such parameters:

SocketName: Name of the socket file to create. /tmp/testimony.sock, that kind of thing. This socket name is given to a connecting client so it can find where/how to communicate with testimonyd.

Interface: Name of the interface to sniff packets on (eth0)

BlockSize: AF_PACKET provides packets to user-space by filling up memory blocks of a specific size, until it either can't fit the next packet into the current block or a timeout is reached. The larger the block, the more packets can be passed to the user at once. BlockSize is in bytes.

NumBlocks: Number of blocks to allocate in memory. NumBlocks * BlockSize is the total size in memory of the AF_PACKET packet memory region for a single fanout.

FanoutSize: The number of memory regions to fan out to. Total memory usage of AF_PACKET is FanoutSize * MemoryRegionSize, where MemoryRegionSize is BlockSize * NumBlocks. FanoutSize can be considered the number of parallel processes that want to access packet data.

BlockTimeoutMillis: If fewer than BlockSize bytes are sniffed by AF_PACKET before this number of milliseconds passes, AF_PACKET provides the current block to users in a less-than-full state.

User: This socket will be owned by the given user, mode 0600. This allows root to provide different sockets with different capabilities to specific users.

Advanced setups
---------------

Multiple testimony servers.
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Suricata can get packets from multiple testimony servers at the same time (each server can sniff packets on different interface)::

    suricata --testimony=/tmp/testimony.sock --testimony=/tmp/testimony2.sock

/etc/testimony2.conf::

    [{ "SocketName": "/tmp/testimony2.sock", 
       "Interface": "eth1",
       "BlockSize": 1048576,
       "NumBlocks": 16,
       "BlockTimeoutMillis": 1000, 
       "FanoutSize": 1, 
       "User": "root"}]