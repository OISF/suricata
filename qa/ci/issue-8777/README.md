# Redmine #8777: FreeBSD netmap VALE regression

`qa/ci/freebsd.sh` runs `test.sh` directly after the unit tests and
Suricata-Verify. This is a **live network test**, not a Suricata-Verify PCAP
replay or a unit test. It requires root, FreeBSD netmap v14+, libnetmap,
`/dev/netmap`, and working VALE software ports. All traffic stays between
`vale0:sender` and `vale0:suri` on the same machine.

Before sending each case, the runner waits up to 60 seconds for Suricata's
`Engine started.` log message while checking that the process is still alive.
A startup timeout or early exit fails the test and prints the startup log.

The sender submits one valid 1000-byte UDP control frame in one slot, then the
same frame in two slots: zero bytes flagged `NS_MOREFRAG`, followed by the
entire frame. Both slots are submitted in **one** TX sync. An empty leading
fragment is supported by headerless VALE ports; it does not make this chain
malformed. Both cases must produce one byte-exact PCAP record and one
tail-marker alert. The script returns nonzero if either assertion fails.
Set `NETMAP_8777_KEEP_RESULTS=1` to retain private captures/logs for debugging;
otherwise temporary results are deleted.

This test fails on unpatched main, which uses the first slot's buffer instead
of reconstructing the frame. PR #16040's coalescing fix and
`NetmapReadZeroLenFragTest` agree with the required result. Land this test
together with or after that fix: it runs unconditionally in the shared
FreeBSD CI job.

This test does **not** cover oversized slot lengths or an incomplete fragment
chain split across two RX reads. A split-TX-sync sender did not provide the
latter layout on FreeBSD 15.1 VALE: it produced two independent RX packets
instead. Do not present this as coverage for those separate hardening cases.

Redmine #8777 is a private security issue. Review disclosure status before
publishing this reproducer or its test results.
