const char configNoChecksum[] = "\
%YAML 1.1\n\
---\n\
pcap-file:\n\
\n\
  checksum-checks: no\n\
\n\
stream:\n\
\n\
  checksum-validation: no\n\
  midstream: true\n\
outputs:\n\
  - fast:\n\
      enabled: yes\n\
      filename: /dev/null\n\
  - eve-log:\n\
      enabled: no\n\
      filetype: regular\n\
      filename: /dev/null\n\
  - http-log:\n\
      enabled: yes\n\
      filename: /dev/null\n\
      extended: yes\n\
  - tls-log:\n\
      enabled: yes\n\
      filename: /dev/null\n\
      extended: yes\n\
app-layer:\n\
  protocols:\n\
    rdp:\n\
      enabled: yes\n\
    modbus:\n\
      enabled: yes\n\
      detection-ports:\n\
        dp: 502\n\
    dnp3:\n\
      enabled: yes\n\
      detection-ports:\n\
        dp: 20000\n\
    enip:\n\
      enabled: yes\n\
      detection-ports:\n\
        dp: 44818\n\
        sp: 44818\n\
    sip:\n\
      enabled: yes\n\
    ssh:\n\
      enabled: yes\n\
      hassh: yes\n\
    mqtt:\n\
      enabled: yes\n\
    http2:\n\
      enabled: yes\n\
";
