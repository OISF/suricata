.. _md5:

Storing MD5s checksums
======================

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

Start Suricata (-S option loads ONLY the specified rule file, with disregard if any other rules that are enabled in suricata.yaml):


::


  suricata -c /etc/suricata/suricata.yaml -S file.rules -i eth0


Meta data:


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

