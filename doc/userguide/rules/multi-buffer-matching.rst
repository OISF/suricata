Multiple Buffer Matching
========================

Suricata 7 and newer now supports matching contents in multiple
buffers within the same transaction.

For example a single DNS transaction that has two queries in it:

query 1: example.net
query 2: something.com

Example rule:

.. container:: example-rule

    `alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:"DNS Multiple Question Example Rule"; dns.query; content:"example"; dns.query; content:".com"; sid:1;)`

Within the single DNS query transaction, there are two queries
and Suricata will set up two instances of a dns.query buffer.

The first ``dns.query`` buffer will look for content:"example";

The second ``dns.query`` buffer will look for content:".com";

The example rule will alert on the example query since all the
content matches are satisfied for the rule.

Existing behavior when using sticky buffers still applies:

Example rule:

.. container:: example-rule

   `alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:"DNS Query Sticky Buffer Classic Example Rule"; dns.query; content:"example"; content:".net"; sid:1;)`

The above rule will alert on a single dns query containing
"example.net" or "example.domain.net" since the rule content
matches are within a single ``dns.query`` buffer and all 
content match requirements of the rule are met.

**Note:** This is new behavior, in versions of Suricata prior to
version 7 multiple statements of the same sticky buffer did not
make a second instance of the buffer. For example:

dns.query; content:"example"; dns.query; content:".com";

would be equivalent to:

dns.query; content:"example"; content:".com";

Using our example from above, the first query is for example.net
which matches content:"example"; but does not match content:".com";

The second query is for something.com which would match on the
content:".com"; but not the content:"example"; 

So with the Suricata behavior prior to Suricata 7, the signature
would not fire in this case since both content conditions will
not be met.

Multiple buffer matching is currently enabled for use with the
following keywords:

``dns.query``
``file.data``
``file.magic``
``file.name``
``http2.header``
``http2.header_name``
``ike.vendor``
``krb5_cname``
``krb5_sname``
``mqtt.subscribe.topic``
``mqtt.unsubscribe.topic``
``quic.cyu.hash``
``quic.cyu.string``
``tls.certs``
``tls.cert_subject``