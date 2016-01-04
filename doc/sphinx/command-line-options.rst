Command Line Options
====================

.. toctree::

   dropping-privileges

You can use command line options in two ways. Using only one line
followed by one character or using two lines followed by a word, like
this:
  
::
  
  -a                   
  --long-option
  
::

  
  -c     The -c option the most important option. After -c you can enter the path to the location of 
         suricata.yaml.
  
  -i     After the -i option you can enter the interface card you would like to use to sniff packets from.
         It concerns sniffing packets with libpcap in the pcap live mode.
  
  -r     After the -r option you can enter the path to the pcap-file in which packets are recorded. That way                 
         you can inspect the packets in that file in the pcap/offline mode.
  
  -s     With the -s option you can set a file with signatures, which will be loaded together with the rules 
         set  in yaml.
  
  -l     With the -l option you can set the default log directory. If you already have the default-log-dir set 
         in yaml, it  will not be used by Suricata if you use the -l option. It will use the log dir that is set 
         with the -l 
         option. If you do not set a directory with the -l option, Suricata will use the directory that is set 
         in yaml.
  
  
  -D     Normally if you run Suricata on your console, it keeps your console occupied. You 
         can not use it for other purposes, and when you close the window, Suricata stops running. 
         If you run Suricata as deamon (using the -D option), it runs at the background and you will be able 
         to use the console for other tasks without disturbing the engine running.
  
  --list-app-layer-protos              : list supported app layer protocols
  
  --list-keywords[=all|csv|<kword>]    : list keywords implemented by the engine
  
  
  --list-runmodes             The option --list-runmodes lists all possible runmodes.
  
  --runmode (in combination with the command line opion -i or -r) 
                              With the --runmode option you can 
                              set the runmode that you would like to use. This command line option can override the    
                              yaml runmode option.

For more information about runmodes see: :doc:`performance/runmodes`

Unit Tests
~~~~~~~~~~
  
::
  
  -u                 With the -u option you can run unit tests to test Suricata's code.
  
  -U                 With the -U option you can select which of the unit tests you want to run. This option uses REGEX.
                     Example of use:
                     suricata -u -U http
  
  --list-unittests   The --list-unittests option shows a list with all possible unit tests.
  
  --fatal-unittests  With the --fatal-unittests option you can run unit tests but it will stop immediately after one test fails
                     so you can see directly where it went wrong.

PF_RING options
~~~~~~~~~~~~~~~

In order to use PF_RING-enabled libpcap, you must start suricata with
the --pfring-int= switch or it will not invoke the PF_RING
enhancements in libpcap.
