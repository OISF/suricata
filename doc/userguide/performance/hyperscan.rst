Hyperscan
=========

Introduction
~~~~~~~~~~~~

"Hyperscan is a high performance regular expression matching library (...)" (https://www.intel.com/content/www/us/en/developer/articles/technical/introduction-to-hyperscan.html)

In Suricata it can be used to perform multi pattern matching (mpm) or single pattern matching (spm).

Support for hyperscan in Suricata was initially implemented by Justin Viiret and Jim Xu from Intel via https://github.com/OISF/suricata/pull/1965.

Hyperscan is only for Intel x86 based processor architectures at this time. For ARM processors, vectorscan is a drop in replacement for hyperscan, https://github.com/VectorCamp/vectorscan. 


Basic Installation (Package)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Some Linux distributions include hyperscan in their respective package collections.

Fedora 37+/Centos 8+: sudo dnf install hyperscan-devel
Ubuntu/Debian: sudo apt-get install libhyperscan-dev


Advanced Installation (Source)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Hyperscan has the following dependencies in order to build from
source:

* boost development libraries (minimum boost library version is 1.58)
* cmake
* C++ compiler (e.g. gcc-c++)
* libpcap development libraries
* pcre2 development libraries
* python3
* ragel
* sqlite development libraries

**Note:** git is an additional dependency if cloning the
hyperscan GitHub repository. Otherwise downloading the
hyperscan zip from the GitHub repository will work too.

The steps to build and install hyperscan are:

::

  git clone https://github.com/intel/hyperscan
  cd hyperscan
  cmake -DBUILD_STATIC_AND_SHARED=1
  cmake --build ./
  sudo cmake --install ./

**Note:** Hyperscan can take a long time to build/compile.

**Note:** It may be necessary to add /usr/local/lib or
/usr/local/lib64 to the `ld` search path. Typically this is
done by adding a file under /etc/ld.so.conf.d/ with the contents
of the directory location of libhs.so.5 (for hyperscan 5.x).


Using Hyperscan
~~~~~~~~~~~~~~~

Confirm that the suricata version installed has hyperscan enabled.
::


  suricata --build-info | grep Hyperscan
    Hyperscan support:                       yes


To use hyperscan support, edit the suricata.yaml.
Change the mpm-algo and spm-algo values to 'hs'.

Alternatively, use this command-line option: --set mpm-algo=hs --set spm-algo=hs

**Note**: The default suricata.yaml configuration settings for
mpm-algo and spm-algo are "auto". Suricata will use hyperscan
if it is present on the system in case of the "auto" setting.


If the current suricata installation does not have hyperscan
support, refer to :ref:`installation`

Hyperscan caching
~~~~~~~~~~~~~~~~~

Upon startup, Hyperscan compiles and optimizes the ruleset into its own
internal structure. Suricata optimizes the startup process by saving
the Hyperscan internal structures to disk and loading them on the next start.
This prevents the recompilation of the ruleset and results in faster
initialization. If the ruleset is changed, new necessary cache files are
automatically created.

To enable this function, in `suricata.yaml` configure:

::

  detect:
    # Cache MPM contexts to the disk to avoid rule compilation at the startup.
    # Cache files are created in the standard library directory.
    sgh-mpm-caching: yes
    sgh-mpm-caching-path: /var/lib/suricata/cache/hs


**Note**:
You might need to create and adjust permissions to the default caching folder
path, especially if you are running Suricata as a non-root user.
