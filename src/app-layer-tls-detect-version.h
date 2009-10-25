#ifndef __APP_LAYER_TLS_DETECT_VERSION_H__
#define __APP_LAYER_TLS_DETECT_VERSION_H__

typedef struct AppLayerTlsDetectVersionData_ {
    uint8_t ver; /** tls version to match */
} AppLayerTlsDetectVersionData;

/* prototypes */
void AppLayerTlsDetectVersionRegister (void);

#endif /* __APP_LAYER_TLS_DETECT_VERSION_H__ */

