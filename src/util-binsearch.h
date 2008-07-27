/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __UTIL_BINSEARCH_H__
#define __UTIL_BINSEARCH_H__

void BinSearchInit (void);
u_int8_t *BinSearch(const u_int8_t *, size_t, const u_int8_t *, size_t);
u_int8_t *BinSearchNocase(const u_int8_t *, size_t, const u_int8_t *, size_t);

#endif /* __UTIL_BINSEARCH_H__ */

