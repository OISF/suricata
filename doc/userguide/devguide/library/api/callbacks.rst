Callbacks
=========

The library allows to register callbacks to be invoked for specific events, as described below.

Flow Callback
~~~~~~~~~~~~~

Callback invoked for any expired flow (equivalent of an EVE flow event).
The function prototype is:

.. code-block:: c

    /**
     * \brief Register a callback that is invoked for every flow.
     *
     * \param ctx            Pointer to SuricataCtx.
     * \param user_ctx       Pointer to a user-defined context object.
     * \param callback       Pointer to a callback function.
     */
    void suricata_register_flow_cb(SuricataCtx *ctx, void *user_ctx, CallbackFuncFlow callback);

This method allows to register a callback represented by the *CallbackFuncFlow* object,
defined as:

.. code-block:: c

    typedef void (CallbackFuncFlow)(
        FlowEvent *flow_event,
        uint64_t *tenant_uuid,
        void *user_ctx
    );

Where:
    * *flow_event* is an object representing the flow. The prototype is:

        .. code-block:: c

            typedef struct {
                /* Packet source IP */
                const char *src_ip;
                /* Packet dest IP */
                const char *dst_ip;
                /* Packet source port */
                uint16_t sp;
                /* Packet dest IP */
                uint16_t dp;
                /* Transport layer protocol */
                const char *proto;
                /* App layer protocol */
                const char *app_proto;
                /* Packet direction */
                const char *direction;
                /* Timestamp */
                char timestamp[TIMESTAMP_LEN];
            } Common;

            typedef struct FlowEvent {
                Common common;

                struct {
                    /* Flow id */
                    int64_t flow_id;
                    /* Parent id */
                    int64_t parent_id;
                    /* Input interface */
                    const char *dev;
                    /* Vland ids */
                    uint16_t vlan_id[2];
                    /* Counters */
                    uint32_t pkts_toserver;
                    uint32_t pkts_toclient;
                    uint64_t bytes_toserver;
                    uint64_t bytes_toclient;
                    /* Timestamps */
                    char start[TIMESTAMP_LEN];
                    char end[TIMESTAMP_LEN];
                    /* Age */
                    int32_t age;
                    /* Emergency flag */
                    uint8_t emergency;
                    /* State */
                    const char *state;
                    /* Reason */
                    const char *reason;
                    /* If flow has alerts */
                    int alerted;
                } flow;
            } FlowEvent;

    * *tenant_uuid* and *user_ctx* are described above.

HTTP Callback
~~~~~~~~~~~~~

Callback invoked for any HTTP event (equivalent of an EVE HTTP event).
The function prototype is:

.. code-block:: c

    /**
     * \brief Register a callback that is invoked for every HTTP event.
     *
     * \param ctx            Pointer to SuricataCtx.
     * \param user_ctx       Pointer to a user-defined context object.
     * \param callback       Pointer to a callback function.
     */
    void suricata_register_http_cb(SuricataCtx *ctx, void *user_ctx, CallbackFuncHttp callback);

This method allows to register a callback represented by the *CallbackFuncHttp* object,
defined as:

.. code-block:: c

    typedef void (CallbackFuncHttp)(
        HttpEvent *http_event,
        uint64_t *tenant_uuid,
        void *user_ctx
    );

Where:
    * *http_event* is an object representing the HTTP transaction. The prototype is:

        .. code-block:: c

            typedef struct Http{
                /* Transaction id, for correlation with other events */
                uint64_t tx_id;
                /* Hostname */
                char *hostname;
                /* Port */
                int http_port;
                /* Uri */
                char *uri;
                /* User agent */
                char *user_agent;
                /* Xff header */
                char *xff;
                /* Content-Type header */
                char *content_type;
            } HttpInfo;

            typedef struct HttpEvent {
                Common common;

                HttpInfo http;
            } HttpEvent;

    * *tenant_uuid* and *user_ctx* are described above.

Alert Callback
~~~~~~~~~~~~~~

Callback invoked for any alert event (equivalent of an EVE alert event).
The function prototype is:

.. code-block:: c

    /**
     * \brief Register a callback that is invoked for every alert.
     *
     * \param ctx            Pointer to SuricataCtx.
     * \param user_ctx       Pointer to a user-defined context object.
     * \param callback       Pointer to a callback function.
     */
    void suricata_register_alert_cb(SuricataCtx *ctx, void *user_ctx, CallbackFuncAlert callback);

This method allows to register a callback represented by the *CallbackFuncAlert* object, defined as:

.. code-block:: c

    typedef void (CallbackFuncAlert)(
        AlertEvent *alert_event,
        uint64_t *tenant_uuid,
        void *user_ctx
    );

Where:
    * *alert_event* is an object representing the alert. The prototype is:

        .. code-block:: c

            typedef struct AlertEvent {
                Common common;

                struct {
                    /* Action for this alert */
                    const char *action;
                    /* Signature relevant fields */
                    uint32_t sid;
                    uint32_t gid;
                    uint32_t rev;
                    int severity;
                    const char *msg;
                    const char *category;
                    const char *metadata;
                    /* Tenant id (suricata) */
                    uint32_t tenant_id_suri;
                } alert;

                /* App layer event information, if any */
                union {
                    HttpInfo *http;
                } app_layer;
            } AlertEvent;

    * *tenant_uuid* is the UUID of the (flow) tenant associated to the alert.

    * *user_ctx* is a pointer to a user-defined context that will be passed along when invoking the
      callback.

Fileinfo Callback
~~~~~~~~~~~~~~~~~

Callback invoked for any fileinfo event (equivalent of an EVE fileinfo event).
The function prototype is:

.. code-block:: c

    /**
     * \brief Register a callback that is invoked for every fileinfo event.
     *
     * \param ctx            Pointer to SuricataCtx.
     * \param user_ctx       Pointer to a user-defined context object.
     * \param callback       Pointer to a callback function.
     */
    void suricata_register_fileinfo_cb(SuricataCtx *ctx, void *user_ctx, CallbackFuncFileinfo callback);

This method allows to register a callback represented by the *CallbackFuncFileinfo* object,
defined as:

.. code-block:: c

    typedef void (CallbackFuncFileinfo)(
        FileinfoEvent *fileinfo_event,
        uint64_t *tenant_uuid,
        void *user_ctx
    );

Where:
    * *fileinfo_event* is an object representing the fileinfo event. The prototype is:

        .. code-block:: c

            typedef struct FileinfoEvent {
                Common common;

                struct {
                    /* File name */
                    const char *filename;
                    /* Magic, if any */
                    const char *magic;
                    /* If the file has gaps */
                    int gaps;
                    /* File state at the moment of logging */
                    const char *state;
                    /* File MD5, if supported */
                    const char *md5;
                    /* File SHA1, if supported */
                    const char *sha1;
                    /* File SHA256, if supported */
                    const char *sha256;
                    /* If the file is stored on disk */
                    int stored;
                    /* File id for a stored file */
                    uint32_t file_id;
                    /* File size */
                    uint64_t size;
                    /* File start */
                    uint64_t start;
                    /* File end */
                    uint64_t end;
                } fileinfo;

                /* App layer event information, if any */
                union {
                    HttpInfo *http;
                } app_layer;
            } FileinfoEvent;

    * *tenant_uuid* and *user_ctx* are described above.

Signature Callback
~~~~~~~~~~~~~~~~~~

Callback invoked for any candidate signature after the prefilter is run. The callback allows to
modify the signature action or discard it according to custom client logic.
The function prototype is:

.. code-block:: c

    /**
     * \brief Register a callback that is invoked before a candidate signature is inspected.
     *
     *        Such callback will be able to decide if a signature is relevant or modify its action
     *         via the return value:
     *         * -1: discard
     *         * 0: inspect signature without modifying its action
     *         * >0: inspect signature but modify its action first with the returned value
     *
     * \param ctx            Pointer to SuricataCtx.
     * \param user_ctx       Pointer to a user-defined context object.
     * \param callback       Pointer to a callback function.
     */
    void suricata_register_sig_cb(SuricataCtx *ctx, void *user_ctx, CallbackFuncSig callback);

This method allows to register a callback represented by the *CallbackFuncSig* object,
defined as:

.. code-block:: c

    typedef int (CallbackFuncSig)(
        uint32_t signature_id,
        uint8_t current_action,
        uint32_t tenant_id,
        uint64_t *tenant_uuid,
        void *user_ctx
    );

Where:
    * *signature_id* is the sid of the candidate signature.

    * *current_action* is the action associated to the signature before any modification.

    * *tenant_id* is the id of the selected detection engine.

    * *tenant_uuid* and *user_ctx* are described above.

