#ifndef __APP_LAYER_PROTOS_H__
#define __APP_LAYER_PROTOS_H__

enum {
    ALPROTO_UNKNOWN = 0,
    ALPROTO_HTTP,
    ALPROTO_FTP,
    ALPROTO_SMTP,
    ALPROTO_SSL, /* SSLv2 */
    ALPROTO_TLS, /* SSLv3 & TLSv1 */
    ALPROTO_SSH,
    ALPROTO_IMAP,
    ALPROTO_MSN,
    ALPROTO_JABBER,
    ALPROTO_SMB,
    ALPROTO_SMB2,
    ALPROTO_DCERPC,
#ifdef UNITTESTS
    ALPROTO_TEST,
#endif /* UNITESTS */
    /* keep last */
    ALPROTO_MAX,
};

typedef struct TlsConfig_ {
    int no_reassemble;
}TlsConfig;

TlsConfig tls;
#endif /* __APP_LAYER_PROTOS_H__ */

