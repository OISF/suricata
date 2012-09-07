/* Copyright (C) 2007-2012 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Roliers Jean-Paul <popof.fpn@gmail.co>
 *
 * Implements cryptographic functions.
 * Based on the libtomcrypt library ( http://libtom.org/?page=features&newsitems=5&whatfile=crypt )
 */

#ifndef UTIL_CRYPT_H_
#define UTIL_CRYPT_H_

#include "suricata-common.h"

typedef enum {
    SC_SHA_1_OK,
    SC_SHA_1_NOK,
    SC_SHA_1_INVALID_ARG,

    SC_BASE64_OK,
    SC_BASE64_INVALID_ARG,
    SC_BASE64_OVERFLOW,

} CryptId;

#ifndef HAVE_NSS

#define LOAD32H(x, y)                            \
     { x = ((unsigned long)((y)[0] & 255)<<24) | \
           ((unsigned long)((y)[1] & 255)<<16) | \
           ((unsigned long)((y)[2] & 255)<<8)  | \
           ((unsigned long)((y)[3] & 255)); }

#define STORE64H(x, y)                                                                     \
   { (y)[0] = (unsigned char)(((x)>>56)&255); (y)[1] = (unsigned char)(((x)>>48)&255);     \
     (y)[2] = (unsigned char)(((x)>>40)&255); (y)[3] = (unsigned char)(((x)>>32)&255);     \
     (y)[4] = (unsigned char)(((x)>>24)&255); (y)[5] = (unsigned char)(((x)>>16)&255);     \
     (y)[6] = (unsigned char)(((x)>>8)&255); (y)[7] = (unsigned char)((x)&255); }

#define STORE32H(x, y)                                                                     \
     { (y)[0] = (unsigned char)(((x)>>24)&255); (y)[1] = (unsigned char)(((x)>>16)&255);   \
       (y)[2] = (unsigned char)(((x)>>8)&255); (y)[3] = (unsigned char)((x)&255); }

#define ROL(x, y) ( (((unsigned long)(x)<<(unsigned long)((y)&31)) | (((unsigned long)(x)&0xFFFFFFFFUL)>>(unsigned long)(32-((y)&31)))) & 0xFFFFFFFFUL)
#define ROLc(x, y) ( (((unsigned long)(x)<<(unsigned long)((y)&31)) | (((unsigned long)(x)&0xFFFFFFFFUL)>>(unsigned long)(32-((y)&31)))) & 0xFFFFFFFFUL)
#ifndef MIN
#define MIN(x, y) ( ((x)<(y))?(x):(y) )
#endif

typedef struct Sha1State_ {
    uint64_t length;
    uint32_t state[5], curlen;
    unsigned char buf[64];
} Sha1State;

typedef union HashState_ {
    char dummy[1];
    Sha1State sha1;
    void *data;
} HashState;

#endif /* don't HAVE_NSS */

unsigned char* ComputeSHA1(unsigned char* buff, int bufflen);
int Base64Encode(const unsigned char *in,  unsigned long inlen, unsigned char *out, unsigned long *outlen);

#endif /* UTIL_CRYPT_H_ */
