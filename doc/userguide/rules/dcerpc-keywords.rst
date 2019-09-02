DCE/RPC
=======
.. role:: example-rule-emphasis

Suricata supports decoding `DCE/RPC <https://en.wikipedia.org/wiki/DCE/RPC>`_
directly in UDP or within SMB via the dcerpc application layer protocol. Because
of this we are able to detect within DCE/RPC the interface UUIDs, operation
numbers, and for bytes within the stub data. This is achieved by using the
keywords ``dcerpc.iface`` and ``dcerpc.opnum``, and the sticky buffer
``dcerpc.stub_data``.


dcerpc.iface
------------
It is necessary for a DCE/RPC client to bind to a service before being able to
call to it. When a client sends a bind request to the server it can specify one
or more interfaces to bind to. Each interface is represented by a UUID. Each
interface UUID is paired with a unique index (or context id) that future
requests can use to reference the service that the client is making a call to.
Using the ``dcerpc.iface`` rule option, we can determine whether or not the
client has bound to a specific interface UUID and whether or not subsequent
client requests are making a request to it. An interface contains a version, and
some versions of an interface may not be vulnerable to a certain exploit. We can
specify a version or range of versions by setting the ``version`` option with
operators. Also, a DCE/RPC request can be broken up into 1 or more fragments.
Flags are set in the DCE/RPC header to indicate whether the fragment is the
first, a middle or the last fragment. Some checks for data in the DCE/RPC
request are only relevant if the DCE/RPC request is a first fragment since
subsequent fragments will contain data deeper into the DCE/RPC request. By
default it is reasonable to only evaluate if the request is a first fragment.
The ``any_frag`` option is used to specify evaluating on all fragments.

Syntax::

  dcerpc.iface:<uuid>[, <operator><version>][, any_frag];

Operator can have the values of::

  <>=!

Version can be::

  0-65535

Syntax Examples::

  dcerpc.iface:4b324fc8-1670-01d3-1278-5a47bf6ee188;
  dcerpc.iface:4b324fc8-1670-01d3-1278-5a47bf6ee188, <2;
  dcerpc.iface:4b324fc8-1670-01d3-1278-5a47bf6ee188, any_frag;
  dcerpc.iface:4b324fc8-1670-01d3-1278-5a47bf6ee188, =1, any_frag;

Signature Example:

.. container:: example-rule

  alert tcp any any -> $HOME_NET any (msg:"TGI LATERAL DCE/RPC Service Control Manager Interface UUID"; :example-rule-emphasis:`dcerpc.iface:367abb81-9844-35f1-ad32-98f038001003;` sid:1;)

Replaces legacy rule option ``dce_iface``.


dcerpc.opnum
------------
Detects operation number, a 16-bit non-negative integer that identifies a
particular operation within the interface being called.

Syntax::

  dcerpc.opnum:<opnum>|<opnum>-<opnum>[, <opnum>|<opnum>-<opnum>];

Opnum can specify a single operation number, a range, or combination thereof.

Syntax Examples::

  dcerpc.opnum:19;
  dcerpc.opnum:12-14,12,121,62-78;
  dcerpc.opnum:12,26,62,61,6513-6666;

Siganture Example:

.. container:: example-rule

  alert tcp any any -> $HOME_NET any (msg:"TGI LATERAL DCE/RPC Service Control Manager Interface UUID with StartServiceW Operation Number"; :example-rule-emphasis:`dcerpc.iface:367abb81-9844-35f1-ad32-98f038001003;` dcerpc.opnum:19; sid:1;)

Replaces legacy rule option ``dce_opnum``.


dcerpc.stub_data
----------------
``dcerpc.stub_data`` is a sticky buffer that points to the buffer containing
the DCE/RPC request or response stub data.

Syntax Example::

  dcerpc.stub_data; content:"%|00|C|00|O|00|M|00|S|00|P|00|E|00|C|00|%";

Signature Example:

.. container:: example-rule

  alert tcp any any -> $HOME_NET any (msg:"TGI LATERAL DCE/RPC stub data contains PSEXEC"; :example-rule-emphasis:`dcerpc.stub_data; content:"P|00|S|00|E|00|X|00|E|00|S|00|V|00|C";` sid:1;)

Replaces legacy rule option ``dce_stub_data``.


