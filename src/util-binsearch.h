/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __UTIL_BINSEARCH_H__
#define __UTIL_BINSEARCH_H__

void BinSearchInit (void);
uint8_t *BinSearch(const uint8_t *, size_t, const uint8_t *, size_t);
uint8_t *BinSearchNocase(const uint8_t *, size_t, const uint8_t *, size_t);

#endif /* __UTIL_BINSEARCH_H__ */

