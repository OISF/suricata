Configuration
=============

After invoking :ref:`suricata_create_ctx`, a default configuration for the library is generated.
A client can further tweaks the library configuration settings via two API methods.

suricata_config_set
~~~~~~~~~~~~~~~~~~~

The function prototype is:

.. code-block:: c

    /**
    * \brief Set a configuration option.
    *
    * \param ctx            Pointer to SuricataCtx.
    * \param key            The configuration option key.
    * \param val            The configuration option value.
    *
    * \return               1 if set, 0 if not set.
    */
    int suricata_config_set(SuricataCtx *ctx, const char *key, const char *val);

The above method will set a configuration option defined by the key *key* with value *val*.
The syntax is the same as the *--set* command line argument provided by the suricata binary.

suricata_config_load
~~~~~~~~~~~~~~~~~~~~
The function prototype is:

.. code-block:: c

    /**
    * \brief Load configuration from file.
    *
    * \param ctx            Pointer to SuricataCtx.
    * \param config_file    Filename of the yaml configuration to load.
    */
    void suricata_config_load(SuricataCtx *ctx, const char *config_file);

This method allows to load a library configuration object from a YAML file, similarly to what
provided by the suricata binary. The syntax for the YAML file is the same as the one used by the
suricata binary.
