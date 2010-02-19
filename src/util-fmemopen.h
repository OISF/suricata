#ifndef __FMEMOPEN_H__
#define __FMEMOPEN_H__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Include this file only for OSX / BSD compilations */
#ifdef OS_DARWIN
#define USE_FMEM_WRAPPER 1
#endif

#ifdef OS_FREEBSD
#define USE_FMEM_WRAPPER 1
#endif

#ifdef OS_WIN32
#define USE_FMEM_WRAPPER 1
#endif

#ifdef USE_FMEM_WRAPPER
FILE *SCFmemopen(void *, size_t, const char *);
#else
/* Else use the normal fmemopen */
#define SCFmemopen fmemopen
#endif

#endif /* __FMEMOPEN_H__ */
