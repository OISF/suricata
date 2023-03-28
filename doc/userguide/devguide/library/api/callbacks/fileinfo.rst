Fileinfo
========

Callback invoked for any fileinfo event (equivalent of an EVE fileinfo event).
The function prototype is:

.. code-block:: c

    /**
    * \brief Register a callback that is invoked for every fileinfo event.
    *
    * \param ctx            Pointer to SuricataCtx.
    * \param callback       Pointer to a callback function.
    */
    void suricata_register_fileinfo_cb(SuricataCtx *ctx, CallbackFuncFileinfo callback);

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
                /* Fields common to all callbacks (5-tuple, timestamp...). */
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
                app_layer app_layer;
            } FileinfoEvent;

    * *tenant_uuid* is the UUID of the (flow) tenant associated to the alert.
    * *user_ctx* is a pointer to a user-defined context that will be passed along when invoking the
      callback.
