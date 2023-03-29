Reject
======

Callback invoked for any Reject event. A reject event is invoked for every packet triggering a
reject signature and allows the client to reject the connection in multiple ways.

All the subsequent packets belonging to the same flow will trigger a reject callback (in case the
flow is not rejected at first attempt) but they will not be inspected by libsuricata.
The function prototype is:

.. code-block:: c

    /**
    * \brief Register a callback that is invoked for every Reject event.
    *
    * \param ctx            Pointer to SuricataCtx.
    * \param callback       Pointer to a callback function.
    */
    void suricata_register_reject_cb(SuricataCtx *ctx, CallbackFuncReject callback);

This method allows to register a callback represented by the *CallbackFuncReject* object,
defined as:

.. code-block:: c

    typedef void (CallbackFuncReject)(
        RejectEvent *reject_event,
        uint64_t *tenant_uuid,
        void *user_ctx
    );

Where:
    * *reject_event* is an object containing the information to reject the connection. The prototype is:

        .. code-block:: c

            /* Reject information included in reject events. */
            typedef struct RejectInfo {
                /* Indicates whether the packet is IPv6. */
                bool pkt_is_ipv6;
                /* TCP info. */
                struct {
                    /* Payload length. */
                    uint16_t payload_len;
                    /* Packet sequence number. */
                    uint32_t seq;
                    /* Packet ACK number. */
                    uint32_t ack;
                    /* Window. */
                    uint16_t win;
                } tcp;
                /* ICMP info. */
                struct {
                    /* Payload (IP header + at most first 8 bytes of IP payload). */
                    uint8_t *payload;
                    /* Payload length. */
                    uint16_t payload_len;
                } icmp;
                /* DNS info. */
                struct {
                    /* Transaction id. */
                    uint16_t query_tx_id;
                    /* Query rrtype. */
                    uint16_t query_rrtype;
                    /* Query rrname. */
                    const uint8_t *query_rrname;
                    /* Query rrname length. */
                    uint32_t query_rrname_len;
                } dns;
            } RejectInfo;

            typedef struct RejectEvent {
                Common common;
                RejectInfo reject;
            } RejectEvent;

    * *tenant_uuid* is the UUID of the (flow) tenant associated to the alert.
    * *user_ctx* is a pointer to a user-defined context that will be passed along when invoking the
      callback.