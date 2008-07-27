#ifndef __HOST_H__
#define __HOST_H__

#include "decode.h"

typedef struct _Host {
    Address addr;
    u_int8_t os;
    u_int8_t reputation;
} Host;

#define HOST_OS_UNKNOWN 0
/* XXX define more */

#define HOST_REPU_UNKNOWN 0
/* XXX see how we deal with this */

#endif /* __HOST_H__ */

