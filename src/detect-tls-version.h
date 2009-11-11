#ifndef __DETECT_TLS_VERSION_H__
#define __DETECT_TLS_VERSION_H__

typedef struct DetectTlsVersionData_ {
    uint8_t ver; /** tls version to match */
} DetectTlsVersionData;

/* prototypes */
void DetectTlsVersionRegister (void);

#endif /* __DETECT_TLS_VERSION_H__ */

