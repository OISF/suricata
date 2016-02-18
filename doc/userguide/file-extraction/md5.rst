.. _md5:

Storing MD5s checksums
======================

In this particular example we are using: Ubuntu 14.04 LTS

Also - we are using the latest git master (git installation)

Make sure you have libnss and libnspr installed
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


::


  root@LTS-64-1:~/Work/tmp/oisf# dpkg -l |grep libnss
  ii  libnss-mdns:amd64                                     0.10-6                                              amd64        NSS module for Multicast DNS name resolution
  ii  libnss3:amd64                                         2:3.17.4-0ubuntu0.14.04.1                           amd64        Network Security Service libraries
  ii  libnss3-1d:amd64                                      2:3.17.4-0ubuntu0.14.04.1                           amd64        Network Security Service libraries - transitional package
  ii  libnss3-dev:amd64                                     2:3.17.4-0ubuntu0.14.04.1                           amd64        Development files for the Network Security Service libraries
  ii  libnss3-nssdb                                         2:3.17.4-0ubuntu0.14.04.1                           all          Network Security Security libraries - shared databases
  ii  libnss3-tools                                         2:3.17.4-0ubuntu0.14.04.1                           amd64        Network Security Service tools



::


  root@LTS-64-1:~/Work/tmp/oisf# dpkg -l |grep libnspr
  ii  libnspr4:amd64                                        2:4.10.7-0ubuntu0.14.04.1                           amd64        NetScape Portable Runtime Library
  ii  libnspr4-dev                                          2:4.10.7-0ubuntu0.14.04.1                           amd64        Development files for the NetScape Portable Runtime library

If not install them:

::


  apt-get install libnss3-dev libnspr4-dev

**Note:** Fedora users need to install the following:

::


  nss-util
  nss-util-devel
  nss-devel
  nspr-devel
  nspr

Get the Suricata code
~~~~~~~~~~~~~~~~~~~~~

Execute:

::


  git clone git://phalanx.openinfosecfoundation.org/oisf.git && cd oisf
  git clone https://github.com/OISF/libhtp.git -b 0.5.x

Building Suricata
~~~~~~~~~~~~~~~~~~

You have to compile/install suri like this in order to enable MD5s:

::


  ./autogen.sh
  ./configure --with-libnss-libraries=/usr/lib --with-libnss-includes=/usr/include/nss/ --with-libnspr-libraries=/usr/lib --with-libnspr-includes=/usr/include/nspr
  make clean
  make
  sudo make install

For Fedora 64-bit users, the configure line will look like


::


  ./configure --with-libnss-libraries=/usr/lib64 --with-libnss-includes=/usr/include/nss3 --with-libnspr-libraries=/usr/lib64 --with-libnspr-includes=/usr/include/nspr4

Output of configure:


::


  Suricata Configuration:
     AF_PACKET support:                       yes
     PF_RING support:                         no
     NFQueue support:                         no
     IPFW support:                            no
     DAG enabled:                             no
     Napatech enabled:                        no

     libnss support:                          yes
     libnspr support:                         yes
     Prelude support:                         no
     PCRE jit:                                no

This is what is important to have:

::


  libnss support:                          yes
  libnspr support:                         yes

Confirm everything is built correctly:


::


  # suricata --build-info
  [10010] 1/5/2012 -- 11:16:23 - (suricata.c:502) <Info> (SCPrintBuildInfo) -- This is Suricata version 1.3dev (rev e6dea5c)
  [10010] 1/5/2012 -- 11:16:23 - (suricata.c:575) <Info> (SCPrintBuildInfo) -- Features: PCAP_SET_BUFF LIBPCAP_VERSION_MAJOR=1 AF_PACKET HAVE_PACKET_FANOUT LIBCAP_NG LIBNET1.1 HAVE_HTP_URI_NORMALIZE_HOOK HAVE_HTP_TX_GET_RESPONSE_HEADERS_RAW HAVE_NSS
  [10010] 1/5/2012 -- 11:16:23 - (suricata.c:589) <Info> (SCPrintBuildInfo) -- 32-bits, Little-endian architecture
  [10010] 1/5/2012 -- 11:16:23 - (suricata.c:591) <Info> (SCPrintBuildInfo) -- GCC version 4.4.5, C version 199901
  [10010] 1/5/2012 -- 11:16:23 - (suricata.c:597) <Info> (SCPrintBuildInfo) -- __GCC_HAVE_SYNC_COMPARE_AND_SWAP_1
  [10010] 1/5/2012 -- 11:16:23 - (suricata.c:600) <Info> (SCPrintBuildInfo) -- __GCC_HAVE_SYNC_COMPARE_AND_SWAP_2
  [10010] 1/5/2012 -- 11:16:23 - (suricata.c:603) <Info> (SCPrintBuildInfo) -- __GCC_HAVE_SYNC_COMPARE_AND_SWAP_4
  [10010] 1/5/2012 -- 11:16:23 - (suricata.c:606) <Info> (SCPrintBuildInfo) -- __GCC_HAVE_SYNC_COMPARE_AND_SWAP_8
  [10010] 1/5/2012 -- 11:16:23 - (suricata.c:613) <Info> (SCPrintBuildInfo) -- compiled with -fstack-protector
  [10010] 1/5/2012 -- 11:16:23 - (suricata.c:619) <Info> (SCPrintBuildInfo) -- compiled with _FORTIFY_SOURCE=2

Make sure we have **HAVE_NSS** in the **Features** line.

Configuration
~~~~~~~~~~~~~

In the suricata yaml:


::


    - file-store:
         enabled: yes       # set to yes to enable
         log-dir: files     # directory to store the files
         force-magic: yes   # force logging magic on all stored files
         force-md5: yes     # force logging of md5 checksums
         #waldo: file.waldo # waldo file to store the file_id across runs

Optionally, for JSON output:


::


   - file-log:
     enabled: yes
     filename: files-json.log
     append: no

Other settings affecting :doc:`file-extraction`


::


  stream:
    memcap: 64mb
    checksum-validation: yes      # reject wrong csums
    inline: no                    # no inline mode
    reassembly:
      memcap: 32mb
      depth: 0                     # reassemble all of a stream
      toserver-chunk-size: 2560
      toclient-chunk-size: 2560

Make sure we have *depth: 0* so all files can be tracked fully.


::


  libhtp:
    default-config:
      personality: IDS
      # Can be specified in kb, mb, gb.  Just a number indicates
      # it's in bytes.
      request-body-limit: 0
      response-body-limit: 0

Make sure we have *request-body-limit: 0* and  *response-body-limit: 0*

Testing
~~~~~~~

For the purpose of testing we use this rule only in a file.rules (a test/example file):


::


  alert http any any -> any any (msg:"FILE store all"; filestore; sid:1; rev:1;)

This rule above will save all the file data for files that are opened/downloaded through HTTP

Start Suricta (-S option loads ONLY the specified rule file, with disregard if any other rules that are enabled in suricata.yaml):


::


  suricata -c /etc/suricata/suricata.yaml -S file.rules -i eth0


I tried that link (Cisco Prod Brochure PDF, just googled "Cisco PDF"):

* http://www.cisco.com/c/en/us/products/routers/3800-series-integrated-services-routers-isr/index.html

and in file directory (/var/log/suricata/files) I got the meta data:



::


  TIME:              05/01/2012-11:09:52.425751
  SRC IP:            2.23.144.170
  DST IP:            192.168.1.91
  PROTO:             6
  SRC PORT:          80
  DST PORT:          51598
  HTTP URI:          /en/US/prod/collateral/routers/ps5855/prod_brochure0900aecd8019dc1f.pdf
  HTTP HOST:         www.cisco.com
  HTTP REFERER:      http://www.cisco.com/c/en/us/products/routers/3800-series-integrated-services-routers-isr/index.html
  FILENAME:          /en/US/prod/collateral/routers/ps5855/prod_brochure0900aecd8019dc1f.pdf
  MAGIC:             PDF document, version 1.6
  STATE:             CLOSED
  MD5:               59eba188e52467adc11bf2442ee5bf57
  SIZE:              9485123

and in files-json.log (or eve.json) :


::


  { "id": 1, "timestamp": "05\/01\/2012-11:10:27.693583", "ipver": 4, "srcip": "2.23.144.170", "dstip": "192.168.1.91", "protocol": 6, "sp": 80, "dp": 51598, "http_uri": "\/en\/US\/prod\/collateral\/routers\/ps5855\/prod_brochure0900aecd8019dc1f.pdf", "http_host": "www.cisco.com", "http_referer": "http:\/\/www.google.com\/url?sa=t&rct=j&q=&esrc=s&source=web&cd=1&ved=0CDAQFjAA&url=http%3A%2F%2Fwww.cisco.com%2Fen%2FUS%2Fprod%2Fcollateral%2Frouters%2Fps5855%2Fprod_brochure0900aecd8019dc1f.pdf&ei=OqyfT9eoJubi4QTyiamhAw&usg=AFQjCNGdjDBpBDfQv2r3VogSH41V6T5x9Q", "filename": "\/en\/US\/prod\/collateral\/routers\/ps5855\/prod_brochure0900aecd8019dc1f.pdf", "magic": "PDF document, version 1.6", "state": "CLOSED", "md5": "59eba188e52467adc11bf2442ee5bf57", "stored": true, "size": 9485123 }
  { "id": 12, "timestamp": "05\/01\/2012-11:12:57.421420", "ipver": 4, "srcip": "2.23.144.170", "dstip": "192.168.1.91", "protocol": 6, "sp": 80, "dp": 51598, "http_uri": "\/en\/US\/prod\/collateral\/routers\/ps5855\/prod_brochure0900aecd8019dc1f.pdf", "http_host": "www.cisco.com", "http_referer": "http:\/\/www.google.com\/url?sa=t&rct=j&q=&esrc=s&source=web&cd=1&ved=0CDAQFjAA&url=http%3A%2F%2Fwww.cisco.com%2Fen%2FUS%2Fprod%2Fcollateral%2Frouters%2Fps5855%2Fprod_brochure0900aecd8019dc1f.pdf&ei=OqyfT9eoJubi4QTyiamhAw&usg=AFQjCNGdjDBpBDfQv2r3VogSH41V6T5x9Q", "filename": "\/en\/US\/prod\/collateral\/routers\/ps5855\/prod_brochure0900aecd8019dc1f.pdf", "magic": "PDF document, version 1.6", "state": "CLOSED", "md5": "59eba188e52467adc11bf2442ee5bf57", "stored": true, "size": 9485123 }


Log all MD5s without any rules
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you would like to log MD5s for everything and anything that passes through the traffic that you are inspecting with Suricata, but not log the files themselves, all you have to do is disable file-store and enable only the JSON output with forced MD5s - in suricata.yaml like so:


::


  - file-store:
      enabled: no       # set to yes to enable
      log-dir: files    # directory to store the files
      force-magic: yes   # force logging magic on all stored files
      force-md5: yes     # force logging of md5 checksums
      #waldo: file.waldo # waldo file to store the file_id across runs

  - file-log:
      enabled: yes
      filename: files-json.log
      append: no
      #filetype: regular # 'regular', 'unix_stream' or 'unix_dgram'
      force-magic: yes   # force logging magic on all logged files
      force-md5: yes     # force logging of md5 checksums

This is in short what is needed to have MD5s logged.
