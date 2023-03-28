Input
=====

The library can receive as input both packets (like the regular Suricata binary) and reassembled
stream segments. This is achieved invoking the following methods.

suricata_handle_packet
~~~~~~~~~~~~~~~~~~~~~~

The function prototype is:

.. code-block:: c

    /**
     * \brief Feed a packet to the library.
     *
     * \param tv                    Pointer to the per-thread structure.
     * \param data                  Pointer to the raw packet.
     * \param datalink              Datalink type.
     * \param ts                    Timeval structure.
     * \param len                   Packet length.
     * \param ignore_pkt_checksum   Boolean indicating if we should ignore the packet checksum.
     * \param tenant_uuid           Tenant uuid (16 bytes) to associate a flow to a tenant.
     * \param tenant_id             Tenant id of the detection engine to use.
     * \return                      Error code.
     */
    int suricata_handle_packet(ThreadVars *tv, const uint8_t *data, int datalink, struct timeval ts,
                               uint32_t len, int ignore_pkt_checksum, uint64_t *tenant_uuid,
                               uint32_t tenant_id);

This method feeds a packet to the Suricata engine. It *must* be invoked from within a Suricata
worker after it has been initialized.

After the packet is processed any relevant registered callback will be invoked.

suricata_handle_stream
~~~~~~~~~~~~~~~~~~~~~~

The function prototype is:

.. code-block:: c

    /** \brief Feed a single stream segment to the library.
     *
     * \param tv                    Pointer to the per-thread structure.
     * \param finfo                 Pointer to the flow information.
     * \param data                  Pointer to the raw packet.
     * \param len                   Packet length.
     * \param tenant_uuid           Tenant uuid (16 bytes) to associate a flow to a tenant.
     * \param tenant_id             Tenant id of the detection engine to use.
     * \return                      Error code.
     */
    int suricata_handle_stream(ThreadVars *tv, FlowInfo *finfo, const uint8_t *data, uint32_t len,
                               uint64_t *tenant_uuid, uint32_t tenant_id);

This method feeds a reassembled stream segment to the Suricata engine. The input parameters are
similar to the packet processing method, except that this method requires a *FlowInfo*
object, defined in the "suricata-interface-stream.h" header as:

.. code-block:: c

    /**
    * \brief Enum representing the stream segment direction.
    *
    * \enum Direction
    */
    enum StreamDirection {
        DIRECTION_TOSERVER = 0,
        DIRECTION_TOCLIENT
    };

    /**
    * \brief Struct representing flow information.
    *
    * \struct FlowInfo
    */
    typedef struct {
        /* Source IP address (in network byte order). */
        struct {
            /* Family. */
            char family;

            union {
                uint32_t        address_un_data32[4]; /* type-specific field */
                uint16_t        address_un_data16[8]; /* type-specific field */
                uint8_t         address_un_data8[16]; /* type-specific field */
            };
        } src;

        /* Source port. */
        uint16_t sp;

        /* Destination IP address (in network byte order). */
        struct {
            // Family.
            char family;

            union {
                uint32_t        address_un_data32[4]; /* type-specific field */
                uint16_t        address_un_data16[8]; /* type-specific field */
                uint8_t         address_un_data8[16]; /* type-specific field */
            };
        } dst;

        /* Destination port. */
        uint16_t dp;

        /* Direction of the stream segment (0 to server, 1 to client). */
        enum StreamDirection direction;

        /* Timestamp of the stream segment. */
        struct timeval ts;
    } FlowInfo;

This method *must* be invoked from within a thread creating a Suricata worker after it has been
initialized.

After the stream segment is processed any relevant registered callback will be invoked.
