#ifndef __APP_LAYER_TLS_H__
#define __APP_LAYER_TLS_H__

#define TLS_FLAG_SERVER_CHANGE_CIPHER_SPEC   0x01    /**< Flag to indicate that
                                                     server will now on sends
                                                     encrypted msgs. */
#define TLS_FLAG_CLIENT_CHANGE_CIPHER_SPEC   0x02    /**< Flag to indicate that
                                                     client will now on sends
                                                     encrypted msgs. */

enum {
    TLS_FIELD_NONE = 0,

    TLS_FIELD_CLIENT_CONTENT_TYPE, /* len 1 */
    TLS_FIELD_CLIENT_VERSION,      /* len 2 */

    TLS_FIELD_SERVER_CONTENT_TYPE, /* len 1 */
    TLS_FIELD_SERVER_VERSION,      /* len 2 */

    TLS_FIELD_LENGTH,
    /* must be last */
    TLS_FIELD_MAX,
};
/* structure to store the TLS state values */
typedef struct TlsState_ {
    uint8_t client_content_type;    /**< Client content type storage field */
    uint16_t client_version;        /**< Client TLS version storage field */

    uint8_t server_content_type;    /**< Server content type storage field */
    uint16_t server_version;        /**< Server TLS version storage field */

    uint8_t flags;                  /**< Flags to indicate the current TLS
                                         sessoin state */
} TlsState;

enum {
    TLS_VERSION_INVALID = 0,
    TLS_VERSION_VALID,
    TLS_VERSION_10,
    TLS_VERSION_11,
    TLS_VERSION_12,
};

void RegisterTLSParsers(void);
void TLSParserRegisterTests(void);

#endif /* __APP_LAYER_TLS_H__ */

