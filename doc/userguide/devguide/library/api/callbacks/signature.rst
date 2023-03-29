Signature
=========

Libsuricata currently offers two callbacks for signatures.

Signature not loaded
~~~~~~~~~~~~~~~~~~~~
Callback invoked for each signature that failed to load.

.. code-block:: c

    /**
    * \brief Register a callback that is invoked for each signature that failed to load.
    *
    * \param ctx            Pointer to SuricataCtx.
    * \param user_ctx       Pointer to a user-defined context object.
    * \param callback       Pointer to a callback function.
    */
    void suricata_register_sig_failed_loading_cb(SuricataCtx *ctx, void *user_ctx, CallbackSigFailedLoading callback);

This method allows to register a callback represented by the *CallbackSigFailedLoading* object,
defined as:

.. code-block:: c

    typedef void (CallbackFuncSigFailedLoading)(
        const char *signature,
        const char *signature_file,
        int line_number,
        void *user_ctx
    );

    typedef struct CallbackSigFailedLoading {
        CallbackFuncSigFailedLoading *func;
        void *user_ctx;
    } CallbackSigFailedLoading;

Where:
    * *signature* is the signature string that failed to load.
    * *signature_file* is the filename of the file containing the signature.
    * *line_number* is the number of the signature within the signature file.
    * *user_ctx* is a pointer to a user-defined context that will be passed along when invoking the
      callback.

Signature candidate
~~~~~~~~~~~~~~~~~~~

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
    void suricata_register_sig_cb(SuricataCtx *ctx, void *user_ctx, CallbackFuncSigCandidate callback);

This method allows to register a callback represented by the *CallbackFuncSigCandidate* object,
defined as:

.. code-block:: c

    typedef int (CallbackFuncSigCandidate)(
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
    * *tenant_uuid* is the UUID of the (flow) tenant associated to the alert.
    * *user_ctx* is a pointer to a user-defined context that will be passed along when invoking the
      callback.
