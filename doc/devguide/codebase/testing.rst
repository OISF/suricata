****************
Testing Suricata
****************

.. contents:: Table of Contents

General Concepts
================

Mainly, there are two ways of testing Suricata.

- Unit tests: for independently checking specific functions or portions of code. This guide has specific sections to
  further explain those, for C and Rust;
- `Suricata-Verify <https://github.com/OISF/suricata-verify>`_: those are used to check more complex behavior, like the log output or the alert counts for a given input, where that input is usually comprised of several packets.

The goal of this document is to offer some guidance regarding when to use each type of test, and how to prepare input
for them.

Unit tests
==========

Use these to check that specific functions behave as expected, in success and in failure scenarios. Specially useful
during development, for
nom parsers in the Rust codebase, for instance, or for checking that messages or message parts of a protocol/stream are processed as they should.

Check the Suricata Devguide on Unit tests for more specificities on how to write or run unit tests.

.. The idea is to have a more detailed page for the unit tests, using what is available in redmine

An example from the `DNS parser <https://github.com/OISF/suricata/blob/master/rust/src/dns/parser.rs#L417>`_. This
checks that the given raw input (note the comments indicating what it means), once processed by ``dns_parse_name`` yields
the expected result, including the unparsed portion.

.. code-block:: rust

    /// Parse a simple name with no pointers.
    #[test]
    fn test_dns_parse_name() {
        let buf: &[u8] = &[
                                                0x09, 0x63, /* .......c */
            0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2d, 0x63, 0x66, /* lient-cf */
            0x07, 0x64, 0x72, 0x6f, 0x70, 0x62, 0x6f, 0x78, /* .dropbox */
            0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, /* .com.... */
        ];
        let expected_remainder: &[u8] = &[0x00, 0x01, 0x00];
        let (remainder,name) = dns_parse_name(buf, buf).unwrap();
        assert_eq!("client-cf.dropbox.com".as_bytes(), &name[..]);
        assert_eq!(remainder, expected_remainder);
    }

From the C side, ``decode-ethernet.c`` offers an good example:

.. code-block:: c

    /**
     * Test a DCE ethernet frame that is too small.
     */
    static int DecodeEthernetTestDceTooSmall(void)
    {
        uint8_t raw_eth[] = {
            0x00, 0x10, 0x94, 0x55, 0x00, 0x01, 0x00, 0x10,
            0x94, 0x56, 0x00, 0x01, 0x89, 0x03,
        };
    
        Packet *p = SCMalloc(SIZE_OF_PACKET);
        FAIL_IF_NULL(p);
        ThreadVars tv;
        DecodeThreadVars dtv;
    
        memset(&dtv, 0, sizeof(DecodeThreadVars));
        memset(&tv,  0, sizeof(ThreadVars));
        memset(p, 0, SIZE_OF_PACKET);
    
        DecodeEthernet(&tv, &dtv, p, raw_eth, sizeof(raw_eth));
    
        FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, DCE_PKT_TOO_SMALL));
    
        SCFree(p);
        PASS;
    }


Generating Input
----------------

Using real traffic
^^^^^^^^^^^^^^^^^^

Having a packet capture for the desired protocol you want to test, open it in `Wireshark <https://www.wireshark.org/>`_, and select the specific
packet chosen for the test input, then use the Wireshark option ``Follow [TCP/UDP/HTTP/HTTP2/QUIC] Stream``. This allows for inspecting the whole network traffic stream in a different window. There, it's possible to choose to ``Show and save data as`` ``C Arrays``, as well as to select if one wants to see the whole conversation or just **client** or **server** packets. It is also possible to reach the same effect by accessing the **Analyze->Follow->TCP Stream** top menu in Wireshark (There are other stream options, the available one will depend on the type of network traffic captured).

This option will show the packet data as hexadecimal compatible with C-array style, and easily adapted for Rust,
as well. As shown in the image:

.. image:: img/InputCaptureExample.png

Wireshark can be also used to `capture sample network traffic <https://gitlab.com/wireshark/wireshark/-/wikis/CaptureSetup>`_ and generate pcap files.

Creating input samples with Scapy
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

It is also possible to use Scapy to craft specific traffic: `Scapy usage
<https://scapy.readthedocs.io/en/latest/usage.html>`_

Suricata-verify tests have several examples of pcaps generated in such a way. Look for Python scripts like the one used
for the `dce-udp-scapy
<https://github.com/OISF/suricata-verify/blob/master/tests/dcerpc/dcerpc-udp-scapy/dcerpc_udp_scapy.py>`_.

Suricata-Verify
===============

As mentioned above, these tests are used to check more complex behavior that involve a complete flow, with exchange of requests and responses. This can be done in an easier and more straightforward way,
since one doesn't have to simulate the network traffic and Suricata engine mechanics - one simply runs it, with the desired input packet capture,
configuration and checks.

A Suricata-verify test can help to ensure that code refactoring doesn't affect protocol logs, or signature detection,
for instance, as this could have a major impact to Suricata users and integrators.

For simpler tests, providing the pcap input is enough. But it is also possible to provide Suricata rules to be
inspected, and have Suricata Verify match for alerts and specific events.

Refer to the `Suricata Verify readme <https://github.com/OISF/suricata-verify#readme>`_ for details on how to create
this type of test. It suffices to have a packet capture representative of the behavior one wants to test, and then
follow the steps described there.

The Git repository for the Suricata Verify tests is a great source for examples, like the `app-layer-template <https://github.com/OISF/suricata-verify/tree/master/tests/app-layer-template>`_ one.

Finding Capture Samples
=======================

If you can't capture traffic for the desired protocol from live traffic, you can try finding the type of traffic you
are interested in public data sets. There's a thread for `Sharing good sources of sample captures
<https://forum.suricata.io/t/sharing-good-sources-of-sample-captures/1766/4>`_ in our forum.
