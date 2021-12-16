*****************
Unit tests - Rust
*****************

Rust tests with Cargo check
===========================

Rust offers a built-in tool for running unit and integration tests. To do so, one makes usage of:

.. code-block:: rust

    cargo test [options][testname][-- test-options]

`The Cargo Book <https://doc.rust-lang.org/cargo/commands/cargo-test.html>`_ explains all options in more detail.

For testing a specific Rust module from Suricata, it suffices to go to the ``rust`` directory and run the above command,
specifying the desired module (like ``http2``).

.. code-block:: rust

    cargo test http2

The line above will make *rustc* compile the Rust side of Suricata and run unit tests in the ``http2`` rust module.

For running all Suricata unit tests from our Rust codebase, just run ``cargo test``.

Adding unit tests
=================

 .. note:: If you want to understand *when* to use a unit test, please read the devguide section on :doc:`testing`.

In general, it is preferable to have the unit tests in the same file that they test. At the end of the file, after all other functions. Add a ``tests`` module, if there isn't one yet, and add the ``#[test]`` attribute before the unit test
function. It is also necessary to import (``use``) the module to test, as well as any other modules used. As seen in the example below:

Example
-------

From ``nfs > rpc_records.rs``:

.. code-block:: rust

   mod tests {
        use crate::nfs::rpc_records::*;
        use nom::Err::Incomplete;
        use nom::Needed::Size;

        #[test]
        fn test_partial_input_ok() {
            let buf: &[u8] = &[
                0x80, 0x00, 0x00, 0x9c, // flags
                0x8e, 0x28, 0x02, 0x7e, // xid
                0x00, 0x00, 0x00, 0x01, // msgtype
                0x00, 0x00, 0x00, 0x02, // rpcver
                0x00, 0x00, 0x00, 0x03, // program
                0x00, 0x00, 0x00, 0x04, // progver
                0x00, 0x00, 0x00, 0x05, // procedure
            ];
            let expected = RpcRequestPacketPartial {
                hdr: RpcPacketHeader {
                        frag_is_last: true,
                        frag_len: 156,
                        xid: 2384986750,
                        msgtype: 1
                    },
                rpcver: 2,
                program: 3,
                progver: 4,
                procedure: 5
            };
            let r = parse_rpc_request_partial(buf);
            match r {
                Ok((rem, hdr)) => {
                    assert_eq!(rem.len(), 0);
                    assert_eq!(hdr, expected);
                },
                _ => { panic!("failed {:?}",r); }
            }
        }
   }

Once that is done, Rust should recognize the new test. If you want to check a single test, run::

    cargo test module::file_name::tests::test_name

Where ``tests`` refers to ``mod tests``. If you know the test name is unique, you can even run::

    cargo test test_name

Following the same idea, it is also possible to test specific modules or submodules. For instance::

    cargo test nfs::rpc_records
