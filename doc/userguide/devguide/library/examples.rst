Examples
========

The repository comes with a sample client that can be used to test the library functionalities.
The client *suricata_client* is located at *examples/suricata_lib/*.

suricata_client
^^^^^^^^^^^^^^^

suricata_client is a simple program able to read one or more files, feed the input to the library
and receive callbacks for the supported events.
The command help is shown below:

.. code-block:: bash

    suricata_client [options] <pcap_file(s)>

    --suricata-config-str          The Suricata command line arguments in the format "arg1=value1;arg2-value2;".
    -h                             Print this help and exit.
    -K, --preload-pcap             Preloads packets into RAM before sending
    -l, --loop=num                 Loop through the capture file(s) X times
    -m, --mode=mode                Set the kind of input to feed to the engine (packet|stream)

    Example usage: ./suricata_client --suricata-config-str "-c=suricata.yaml;-l=.;--runmode=offline" input.pcap

The client accepts a configuration string in the *--suricata-config-str* argument in the format
described in :ref:`suricata_init` from the :doc:`api/index` section and one or more input files.
It then initializes the library registering the callbacks (which print some fields
of the relevant event) and creates a separate worker thread for each input file.
At the end of the processing, some performance stats are printed to stdout.

Currently suricata_client supports two run modes defined by the *-m* option:

* Packet mode: default run mode which assumes the input is one or more PCAP files.
* Stream mode: run mode which assumes the input is one or more Stream files.

The Stream format is a custom format where one line corresponds to a stream segment and contains
the following comma separated information:

* Timestamp.
* IP version (4/6).
* Segment direction.
* Segment source IP address.
* Segment destination IP address.
* Segment source port.
* Segment destination port.
* Payload length.
* Payload base64 encoded.

The *pcap2stream.py* helper script located at the *script* directory is a utility tool that
receives a .pcap file as input and converts it into its .stream equivalent.

The client also provides support for preloading the input files from disk with the *-K* option and
for looping over the files for a specified number of iterations with the *-l* option. These are
mainly intended for performance testing.
