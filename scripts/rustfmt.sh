#! /usr/bin/env bash
# Check rust formatting, not complete yet

set -e

(
cd rust/derive
cargo fmt --check
)

(
cd rust/htp
cargo fmt --check
)

(
cd rust/ffi
cargo fmt --check
)

(
cd rust/suricatactl
cargo fmt --check
)

(
cd rust/suricatasc
cargo fmt --check
)

(
cd rust/sys
cargo fmt --check
)

rustfmt --check rust/src/dns/*.rs rust/src/applayertemplate/*.rs rust/src/asn1/*.rs \
    rust/src/bittorrent_dht/*.rs rust/src/enip/*.rs rust/src/ffi/*.rs rust/src/ftp/*.rs \
    rust/src/ldap/*.rs rust/src/mime/*.rs rust/src/ntp/*.rs rust/src/quic/*.rs \
    rust/src/rfb/*.rs rust/src/ssh/*.rs rust/src/utils/*.rs rust/src/websocket/*.rs \
    rust/src/dhcp/*.rs rust/src/krb/*.rs rust/src/mdns/*.rs rust/src/pop3/*.rs \
    rust/src/http2/*.rs rust/src/ike/*.rs rust/src/modbus/*.rs rust/src/mqtt/*.rs \
    rust/src/nfs/*.rs rust/src/pgsql/*.rs rust/src/rdp/*.rs rust/src/sdp/*.rs \
    rust/src/sip/*.rs rust/src/telnet/*.rs rust/src/tftp/*.rs rust/src/x509/*.rs
