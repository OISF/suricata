/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __UTIL_MPM_WUMANBER_H__
#define __UTIL_MPM_WUMANBER_H__

#include "util-mpm.h"

#define NOCASE 0x01

typedef struct _WmPattern {
    u_int8_t *cs; /* case sensitive */
    u_int8_t *ci; /* case INsensitive */
    u_int16_t len;
    struct _WmPattern *next;
    u_int16_t prefix_ci;
    u_int16_t prefix_cs;
    u_int8_t flags;
    MpmEndMatch *em;
} WmPattern;

typedef struct _WmHashItem_ {
    u_int8_t flags;
    u_int16_t idx;
    struct _WmHashItem_ *nxt;
} WmHashItem;

typedef struct _WmCtx {
    /* hash used during ctx initialization */
    WmPattern **init_hash;

    u_int16_t shiftlen;

    u_int32_t hash_size;
    WmHashItem **hash;
    WmHashItem hash1[256];
    /* we store our own multi byte search ptr here for WmSearch1 */
    u_int32_t (*MBSearch)(struct _MpmCtx *, struct _MpmThreadCtx *, u_int8_t *, u_int16_t);

    /* pattern arrays */
    WmPattern **parray;

    /* only used for multibyte pattern search */
    u_int16_t *shifttable;
} WmCtx;

typedef struct _WmThreadCtx {
    u_int32_t stat_shift_null;
    u_int32_t stat_loop_match;
    u_int32_t stat_loop_no_match;
    u_int32_t stat_num_shift;
    u_int32_t stat_total_shift;
} WmThreadCtx;

void MpmWuManberRegister(void);

#endif /* __UTIL_MPM_WUMANBER_H__ */

