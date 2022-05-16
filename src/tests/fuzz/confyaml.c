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
      enabled: yes\n\
      filetype: regular\n\
      filename: /dev/null\n\
      xff:\n\
        enabled: yes\n\
        mode: extra-data\n\
        deployment: reverse\n\
        header: X-Forwarded-For\n\
      types:\n\
        - alert:\n\
            payload: yes\n\
            payload-printable: yes\n\
            packet: yes\n\
            metadata: yes\n\
            http-body: yes\n\
            http-body-printable: yes\n\
            tagged-packets: yes\n\
        - anomaly:\n\
            enabled: yes\n\
            types:\n\
              decode: yes\n\
              stream: yes\n\
              applayer: yes\n\
            packethdr: yes\n\
        - http:\n\
            extended: yes\n\
            dump-all-headers: both\n\
        - dns\n\
        - tls:\n\
            extended: yes\n\
            session-resumption: yes\n\
        - files\n\
        - smtp:\n\
            extended: yes\n\
        - dnp3\n\
        - ftp\n\
        - rdp\n\
        - nfs\n\
        - smb\n\
        - tftp\n\
        - ike\n\
        - krb5\n\
        - snmp\n\
        - rfb\n\
        - sip\n\
        - dhcp:\n\
            enabled: yes\n\
            extended: yes\n\
        - ssh\n\
        - pgsql\n\
        - flow\n\
        - netflow\n\
        - metadata\n\
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
    template:\n\
      enabled: yes\n\
    template-rust:\n\
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
    pgsql:\n\
      enabled: yes\n\
    http2:\n\
      enabled: yes\n\
    quic:\n\
      enabled: yes\n\
";
