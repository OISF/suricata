# Napatech Plugin Capture Plugin

## Building

To build this plugin, configure Suricata with the `--enable-napatech` and
optionally the `--with-napatech-includes` and
`--with-napatech-libraries` command line options.

## Running
```
/usr/local/suricata/bin/suricata \
    --set plugins.0=/usr/local/lib/suricata/napatech.so \
    --capture-plugin=napatech
```

### --set plugins.0=/usr/local/lib/suricata/napatech.so

This command line option tells Suricata about this plugin. This could also
be done in `suricata.yaml` with the following section:
```
plugins:
  - /usr/local/lib/suricata/napatech.so
```

### --capture-plugin=napatech

This is the option that tells Suricata to use a plugin for capture, much like
`--pcap` tells Suricata to use libpcap or `--af-packet` tells Suricata to use
AF_PACKET. Here we are telling it to look for a loaded plugin of the name
`napatech` to provide the capture method.

There is another command line option `--capture-plugin-args` to pass arbitrary
data on the command line to a capture plugin, but this plugin does not yet handle
data provided through this command line parameter.
