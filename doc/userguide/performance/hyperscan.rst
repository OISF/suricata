Hyperscan
=========

Introduction
~~~~~~~~~~~~

"Hyperscan is a high performance regular expression matching library..." https://www.intel.com/content/www/us/en/developer/articles/technical/introduction-to-hyperscan.html

In Suricata it can be used to perform multi pattern matching (mpm) or single pattern matching (spm).

Support for hyperscan in Suricata was initially implemented by Justin Viiret and Jim Xu from Intel via https://github.com/OISF/suricata/pull/1965.


Using Hyperscan
~~~~~~~~~~~~~~~

Confirm that the suricata version installed has hyperscan enabled.
::


  suricata --build-info | grep Hyperscan
    Hyperscan support:                       yes


To use hyperscan support, edit the suricata.yaml. Change the mpm-algo and spm-algo values to 'hs'.

Alternatively, use this commandline option: --set mpm-algo=hs --set spm-algo=hs

**Notes**: The default suricata.yaml configuration settings for mpm-algo and spm-algo are "auto" which will use Hyperscan if it is present on the system.


If the current installation does not have hyperscan support, refer to :ref:`installation`