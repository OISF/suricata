Hyperscan
=========

Introduction
~~~~~~~~~~~~

"Hyperscan is a high-performance multiple regex matching library." https://www.hyperscan.io

In Suricata it can be used to perform multi pattern matching (mpm). Support was implemented by Justin Viiret and Jim Xu from Intel: https://github.com/inliniac/suricata/pull/1965, https://redmine.openinfosecfoundation.org/issues/1704

Compilation
~~~~~~~~~~~

It's possible to pass --with-libhs-includes=/usr/local/include/hs/ --with-libhs-libraries=/usr/local/lib/, although by default this shouldn't be necessary. Suricata should pick up Hyperscan's pkg-config file automagically.

When Suricata's compilation succeeded, you should have:

::


  suricata --build-info|grep Hyperscan
    Hyperscan support:                       yes


Using Hyperscan
~~~~~~~~~~~~~~~

To use the hyperscan support edit your suricata.yaml. Change the mpm-algo and spm-algo values to 'hs'.

Alternatively, use this command-line option: --set mpm-algo=hs --set spm-algo=hs




Ubuntu Hyperscan Installation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To use Suricata with Hyperscan support, install dependencies:


::


  apt-get install cmake ragel

libboost headers
----------------

Hyperscan needs the libboost headers from 1.58+.

On Ubuntu 15.10 or 16.04+, simply do:


::


  apt-get install libboost-dev


Trusty
------

Trusty has 1.57, so it's too old. We can grab a newer libboost version, but we *don't* install it system wide. It's only the headers we care about during compilation of Hyperscan.


::


  sudo apt-get python-dev libbz2-dev
  wget https://dl.bintray.com/boostorg/release/1.66.0/source/boost_1_66_0.tar.gz
  tar xvzf boost_1_66_0.tar.gz
  cd boost_1_66_0
  ./bootstrap.sh --prefix=~/tmp/boost-1.66
  ./b2 install

Hyperscan
---------

We'll install version 5.0.0.


::


  git clone https://github.com/intel/hyperscan
  cd hyperscan
  mkdir build
  cd build
  cmake -DBUILD_STATIC_AND_SHARED=1 ../

If you have your own libboost headers, use this cmake line instead:

::


  cmake -DBUILD_STATIC_AND_SHARED=1 -DBOOST_ROOT=~/tmp/boost-1.66 ../

Finally, make and make install:

::


  make
  sudo make install

Compilation can take a long time, but it should in the end look something like this:


::


  Install the project...
  -- Install configuration: "RELWITHDEBINFO"
  -- Installing: /usr/local/lib/pkgconfig/libhs.pc
  -- Up-to-date: /usr/local/include/hs/hs.h
  -- Up-to-date: /usr/local/include/hs/hs_common.h
  -- Up-to-date: /usr/local/include/hs/hs_compile.h
  -- Up-to-date: /usr/local/include/hs/hs_runtime.h
  -- Installing: /usr/local/lib/libhs_runtime.a
  -- Installing: /usr/local/lib/libhs_runtime.so.4.2.0
  -- Installing: /usr/local/lib/libhs_runtime.so.4.2
  -- Installing: /usr/local/lib/libhs_runtime.so
  -- Installing: /usr/local/lib/libhs.a
  -- Installing: /usr/local/lib/libhs.so.4.2.0
  -- Installing: /usr/local/lib/libhs.so.4.2
  -- Installing: /usr/local/lib/libhs.so

Note that you may have to add /usr/local/lib to your ld search path


::


  echo "/usr/local/lib" | sudo tee --append /etc/ld.so.conf.d/usrlocal.conf
  sudo ldconfig

