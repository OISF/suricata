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

    -c <path>                                Path to (optional) configuration file.
    -h                                       Print this help and exit.
    -l <dir>                                 Path to log directory.
    -K, --preload-pcap                       Preloads packets into RAM before sending
    -L <num>, --loop=num                     Loop through the capture file(s) X times
    -m <mode>, --mode=mode                   Set the kind of input to feed to the engine (packet|stream)
    -o <output>, --output=output             Path of the EVE output file (eve.json by default)
    -s <name=value>, --set name=value        Set a configuration value
    -S <path>                                Absolute path to signature file loaded exclusively

    Example usage: ./suricata_client -c suricata.yaml input.pcap

The client accepts one or more input files, it initializes the library registering the callbacks
and creates a separate worker thread for each input file.
At the end of the processing, some performance stats are printed to stdout.

The library can be configured using a YAML file and the *-c* option. Additional configuration
options can be specified with the *--set* options (same as the suricata binary).

Rule files to load can be either set in the configuraion yaml in the *rule-files* array or a
single rule path can be specified with the *-S* option.

The callbacks will dump the events in JSON format (basically the same as the suricata binary EVE
logging) in a logging directory defined by the *-l* option and in an output file defined by the
*-o* option.

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
for looping over the files for a specified number of iterations with the *-L* option. These are
mainly intended for performance testing.
