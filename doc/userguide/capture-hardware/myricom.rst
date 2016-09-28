Myricom
=======

From: http://blog.inliniac.net/2012/07/10/suricata-on-myricom-capture-cards/

In this guide I’ll describe using the Myricom libpcap support. I’m going to assume you installed the card properly, installed the Sniffer driver and made sure that all works. Make sure that in your dmesg you see that the card is in sniffer mode:

::


  [ 2102.860241] myri_snf INFO: eth4: Link0 is UP
  [ 2101.341965] myri_snf INFO: eth5: Link0 is UP

I have installed the Myricom runtime and libraries in /opt/snf

Compile Suricata against Myricom’s libpcap:


::


  ./configure --with-libpcap-includes=/opt/snf/include/ --with-libpcap-libraries=/opt/snf/lib/ --prefix=/usr --sysconfdir=/etc --localstatedir=/var
  make
  sudo make install

Next, configure the amount of ringbuffers. I’m going to work with 8 here, as my quad core + hyper threading has 8 logical CPU’s. *See below* for additional information about the buffer-size parameter.


::


  pcap:
    - interface: eth5
      threads: 8
      buffer-size: 512kb
      checksum-checks: no

The 8 threads setting makes Suricata create 8 reader threads for eth5. The Myricom driver makes sure each of those is attached to it’s own ringbuffer.

Then start Suricata as follows:

::


  SNF_NUM_RINGS=8 SNF_FLAGS=0x1 suricata -c suricata.yaml -i eth5 --runmode=workers

If you want 16 ringbuffers, update the “threads” variable in your yaml to 16 and start Suricata:

::


  SNF_NUM_RINGS=16 SNF_FLAGS=0x1 suricata -c suricata.yaml -i eth5 --runmode=workers

Note that the pcap.buffer-size yaml setting shown above is currently ignored when using Myricom cards. The value is passed through to the pcap_set_buffer_size libpcap API within the Suricata source code. From Myricom support:

::


  “The libpcap interface to Sniffer10G ignores the pcap_set_buffer_size() value.  The call to snf_open() uses zero as the dataring_size which informs the Sniffer library to use a default value or the value from the SNF_DATARING_SIZE environment variable."

The following pull request opened by Myricom in the libpcap project indicates that a future SNF software release could provide support for setting the SNF_DATARING_SIZE via the pcap.buffer-size yaml setting:

* https://github.com/the-tcpdump-group/libpcap/pull/435

Until then, the data ring and descriptor ring values can be explicitly set using the SNF_DATARING_SIZE and SNF_DESCRING_SIZE environment variables, respectively.

The SNF_DATARING_SIZE is the total amount of memory to be used for storing incoming packet data. This size is shared across all rings.
The SNF_DESCRING_SIZE is the total amount of memory to be used for storing meta information about the packets (packet lengths, offsets, timestamps). This size is also shared across all rings.

Myricom recommends that the descriptor ring be 1/4 the size of the data ring, but the ratio can be modified based on your traffic profile.
If not set explicitly, Myricom uses the following default values: SNF_DATARING_SIZE = 256MB, and SNF_DESCRING_SIZE = 64MB

Expanding on the 16 thread example above, you can start Suricata with a 16GB Data Ring and a 4GB Descriptor Ring using the following command:

::


  SNF_NUM_RINGS=16 SNF_DATARING_SIZE=17179869184 SNF_DESCRING_SIZE=4294967296 SNF_FLAGS=0x1 suricata -c suricata.yaml -i eth5 --runmode=workers

Debug Info
~~~~~~~~~~

Myricom also provides a means for obtaining debug information. This can be useful for verifying your configuration and gathering additional information.
Setting SNF_DEBUG_MASK=3 enables debug information, and optionally setting the SNF_DEBUG_FILENAME allows you to specify the location of the output file.

Following through with the example:

::


  SNF_NUM_RINGS=16 SNF_DATARING_SIZE=17179869184 SNF_DESCRING_SIZE=4294967296 SNF_FLAGS=0x1 SNF_DEBUG_MASK=3 SNF_DEBUG_FILENAME="/tmp/snf.out" suricata -c suricata.yaml -i eth5 --runmode=workers

Additional Info
~~~~~~~~~~~~~~~

* http://www.40gbe.net/index_files/be59da7f2ab5bf0a299ab99ef441bb2e-28.html

* http://o-www.emulex.com/blogs/implementers/2012/07/23/black-hat-usa-2012-emulex-faststack-sniffer10g-product-demo-emulex-booth/
