:orphan: Linked from install page, just not a TOC.

Building on Windows
###################

The following are instructions for building Suricata on Windows in an
MSYS2 environment. This is targeted to users who plan to develop
Suricata, or create Suricata packages for Windows. For end users we
recommend the Windows installer available on the Suricata download
page: https://suricata.io/download/

Dependencies
************

Before building on Windows, the following dependencies must be
installed:

* MSYS2: MSYS2 provides the Windows build environment required by
  Suricata. Install from https://www.msys2.org/.

* Npcap for Windows: This is required for live capture on Windows. If
  only PCAP processing is desired, this dependency can be skipped. The
  "Npcap Installer" package as well as the "Npcap SDK" need to be
  installed. Download from https://npcap.com/.

MSYS2
=====

First, MSYS2 must be installed. This can be done with the MSYS2
installer from https://www.msys2.org/.

Once installed, the following directions assume the default ``UCRT64``
environment will be used.

MSYS2 Dependencies
------------------

Prepare your MSYS2 development environment by installing the following
dependencies::

  pacman -S \
    autoconf \
    automake \
    git \
    make \
    mingw-w64-ucrt-x86_64-cbindgen \
    mingw-w64-ucrt-x86_64-jansson \
    mingw-w64-ucrt-x86_64-libpcap \
    mingw-w64-ucrt-x86_64-libtool \
    mingw-w64-ucrt-x86_64-libyaml \
    mingw-w64-ucrt-x86_64-pcre2 \
    mingw-w64-ucrt-x86_64-rust \
    mingw-w64-ucrt-x86_64-toolchain \
    unzip

.. note:: If asked to enter a selection, particularly for the
          toolchain dependency, select the default of ``all``.

Npcap
=====

Npcap is required for live capture on Windows. The driver and the SDK
must be installed to build Suricata on Windows with live capture
support.

Both the driver installers and the SDK can be downloaded from
https://npcap.com/.

Npcap Driver
------------

The driver is a native Windows application installer. Install it using
the downloaded installer.

Npcap SDK
---------

The SDK can be installed from Windows, or from inside the MSYS2
environment. The following documentation assumes the SDK was installed
inside the MSYS2 environment like so::

  curl -OL https://npcap.com/dist/npcap-sdk-1.15.zip
  unzip npcap-sdk-1.15.zip -d /npcap

Building
********

::

   ./autogen.sh
   ./configure --prefix=/usr/local \
       --with-libpcap-includes=/c/npcap/Include \
       --with-libpcap-libraries=/c/npcap/Lib/x64

.. note:: If intentionally building without ``Npcap`` support you can
          leave off the ``--with-libpcap`` configure options, and the
          MSYS2 libpcap will be used without live capture support.

Installation
************

To install in the MSYS2 environment, run::

  make install

.. attention:: At this time, ``make install-conf`` and ``make
               install-full`` do not work properly. See ticket
               https://redmine.openinfosecfoundation.org/issues/7763
               for details. You will manually need to copy
               configuration files, and/or update command line and
               configuration file options to find relevant
               configuration files to run inside the MSYS2
               environment.
