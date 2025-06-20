# Suricata Reserved SID Allocations

Unless otherwise noted, each component or protocol is allocated 1000
signature IDs.

## Components

| Component         | Start   | End     |
| ----------------- | ------- | ------- |
| Decoder           | 2200000 | 2200999 |
| Stream            | 2210000 | 2210999 |
| Generic App-Layer | 2260000 | 2260999 |

## App-Layer Protocols

| Protocol | Start   | End     |
| -------- | ------- | ------- |
| SMTP     | 2220000 | 2220999 |
| HTTP     | 2221000 | 2221999 |
| NTP      | 2222000 | 2222999 |
| NFS      | 2223000 | 2223999 |
| IPsec    | 2224000 | 2224999 |
| SMB      | 2225000 | 2225999 |
| Kerberos | 2226000 | 2226999 |
| DHCP     | 2227000 | 2227999 |
| SSH      | 2228000 | 2228999 |
| MQTT     | 2229000 | 2229999 |
| TLS      | 2230000 | 2230999 |
| QUIC     | 2231000 | 2231999 |
| FTP      | 2232000 | 2232999 |
| POP3     | 2236000 | 2236999 |
| DNS      | 2240000 | 2240999 |
| PGSQL    | 2241000 | 2241999 |
| mDNS     | 2242000 | 2242999 |
| MODBUS   | 2250000 | 2250999 |
| DNP3     | 2270000 | 2270999 |
| HTTP2    | 2290000 | 2290999 |
