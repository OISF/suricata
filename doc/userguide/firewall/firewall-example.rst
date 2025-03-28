Firewall Ruleset Examples
=========================

.. note:: In Suricata 8 the firewall mode is experimental and subject to change.

HTTP
----

In this example a simple HTTP ruleset will be shown. It will allow HTTP to flow
as long as:

- method is GET or POST
- User-Agent is "curl"
- Status code is 200.

It starts by allowing the TCP port 80 traffic.

::

    accept:hook tcp:all any any <> any 80 (sid:10;)

The stream tracking combined with the default exception policy handling will enforce
a proper TCP handshake, etc.

The HTTP rules need to ``accept`` each state::

    # allow traffic before the request line is complete
    accept:hook http1:request_started any any -> any any (sid:100;)
    # allow GET
    accept:hook http1:request_line any any -> any any ( \
            http.method; content:"GET"; sid:101;)
    # or allow POST
    accept:hook http1:request_line any any -> any any ( \
            http.method; content:"POST"; sid:102;)
    # allow User-Agent curl
    accept:hook http1:request_headers any any -> any any ( \
            http.user_agent; content:"curl"; sid:103;)
    # allow the body, if any
    accept:hook http1:request_body any any -> any any (sid:104;)
    # allow trailers, if any
    accept:hook http1:request_trailer any any -> any any (sid:105;)
    # allow completion
    accept:hook http1:request_complete any any -> any any (sid:106;)

    # allow traffic before the response line is complete
    accept:hook http1:response_started any any -> any any (sid:200;)
    # allow the 200 ok stat code.
    accept:hook http1:response_line any any -> any any ( \
            http.stat_code; content:"200"; sid:201;)
    # allow all other states
    accept:hook http1:response_headers any any -> any any (sid:202;)
    accept:hook http1:response_body any any -> any any (sid:203;)
    accept:hook http1:response_trailer any any -> any any (sid:204;)
    accept:hook http1:response_complete any any -> any any (sid:205;)

Each state needs an ``accept`` rule. Each state is evaluated at least once.

TLS SNI with complex TCP rules
------------------------------

In this example the ``packet_filter`` rules will be more opinionated about the traffic::

    # allow 3-way handshake
    accept:hook tcp:all $HOME_NET any -> $EXTERNAL_NET 443 (flags:S; \
            flow:not_established; flowbits:set,syn; sid:1;)
    accept:hook tcp:all $EXTERNAL_NET 443 -> $HOME_NET any (flags:SA; \
            flow:not_established; flowbits:isset,syn; flowbits:set,synack; sid:2;)
    accept:hook tcp:all $HOME_NET any -> $EXTERNAL_NET 443 (flags:A; \
            flow:not_established; flowbits:isset,synack;             \
            flowbits:unset,syn; flowbits:unset,synack; sid:3;)
    # allow established
    accept:hook tcp:all $HOME_NET any <> $EXTERNAL_NET 443 (flow:established; sid:4;)

Then on the TLS level this will be a TLS SNI firewall.

Again all the states need to be accepted. Only in the ``client_hello_done`` state will
there be additional constraints::

    accept:hook tls:client_in_progress $HOME_NET any -> $EXTERNAL_NET any (sid:100;)
    # allow the good sites
    accept:hook tls:client_hello_done $HOME_NET any -> $EXTERNAL_NET any (tls.sni; \
            pcre:"/^(suricata.io|oisf.net)$/; sid:101;)
    accept:hook tls:client_cert_done $HOME_NET any -> $EXTERNAL_NET any (sid:102;)
    accept:hook tls:client_handshake_done $HOME_NET any -> $EXTERNAL_NET any (sid:103;)
    accept:hook tls:client_finished $HOME_NET any -> $EXTERNAL_NET any (sid:104;)

    accept:hook tls:server_in_progress $EXTERNAL_NET any -> $HOME_NET any (sid:200;)
    accept:hook tls:server_hello $EXTERNAL_NET any -> $HOME_NET any (sid:201;)
    accept:hook tls:server_cert_done $EXTERNAL_NET any -> $HOME_NET any (sid:202;)
    accept:hook tls:server_hello_done $EXTERNAL_NET any -> $HOME_NET any (sid:203;)
    accept:hook tls:server_handshake_done $EXTERNAL_NET any -> $HOME_NET any (sid:204;)
    accept:hook tls:server_finished $EXTERNAL_NET any -> $HOME_NET any (sid:205;)

