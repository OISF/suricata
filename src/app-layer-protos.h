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
    ALPROTO_DCERPC,

    /* keep last */
    ALPROTO_MAX,
};

#endif /* __APP_LAYER_PROTOS_H__ */

