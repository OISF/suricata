/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *
 * Implements ASN1 decoding (needed for the asn1 keyword)
 */

#ifndef __DECODE_ASN1_H__
#define __DECODE_ASN1_H__
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <limits.h>
#include <ctype.h>
#include <string.h>

#define ASN1_MAX_FRAMES 128

/* For future enconding type implementations */
enum {
    ASN1_BER_ENC,
    ASN1_ENC_UNKNOWN
};

/* Class of tag */
#define ASN1_BER_CLASS_UNIV                 0
#define ASN1_BER_CLASS_APP                  1
#define ASN1_BER_CLASS_CTX_SPECIFIC         2
#define ASN1_BER_CLASS_PRIV                 3

/* For low tag numbers */
#define ASN1_BER_GET_CLASS_TAG(id_octet)    \
             ((id_octet >> 6) & 0x03)           /* (8.1.2.2a) */
#define ASN1_BER_IS_CONSTRUCTED(id_octet)   \
             ((id_octet >> 5) & 0x01)           /* (8.1.2.5) Constructed Tag */
#define ASN1_BER_IS_PRIMITIVE(id_octet)     \
             (((id_octet >> 5) & 0x01)?0:1)     /* (8.1.2.5) Primitive Tag */
#define ASN1_BER_IS_LOW_TAG(id_octet)       \
             ASN1_BER_IS_PRIMITIVE(id_octet)    /* (8.1.2.5) Is Low Tag
                                                             Number */
#define ASN1_BER_GET_LOW_TAG_NUM(id_octet)  \
             (id_octet & 0x1F)                  /* (8.1.2.2c) Get LowTag Number */

/* For high tag numbers */
#define ASN1_BER_IS_HIGH_TAG(id_octet)      \
        ((ASN1_BER_GET_LOW_TAG_NUM(id_octet) == 0x1F) && \
        ASN1_BER_IS_CONSTRUCTED(id_octet))      /* (8.1.2.4) High Tag Number */
#define ASN1_BER_IS_HIGH_TAG_END(id_octet)  \
        ( !((id_octet >> 7) & 0x01))            /* (8.1.2.4) Is End of Tag Num */
#define ASN1_BER_GET_HIGH_TAG_NUM(id_octet) \
        (id_octet & 0x7F)                       /* (8.1.2.4) Part of High Tag
                                                             Number */


#define ASN1_BER_IS_SHORT_LEN(id_octet)        \
             ( !((id_octet >> 7) & 0x01))        /* (8.1.3.3) Is short form */
#define ASN1_BER_GET_SHORT_LEN(id_octet)       \
             (id_octet & 0x7F)                   /* (8.1.3.3) length value */
#define ASN1_BER_GET_LONG_LEN_OCTETS(id_octet) \
             (id_octet & 0x7F)                   /* (8.1.3.5) the number of
                                                              bytes */
#define ASN1_BER_GET_LONG_LEN(id_octet) \
             (id_octet)                          /* (8.1.3.5) the byte itself*/
#define ASN1_BER_LONG_LEN_HAS_NEXT(id_octet)   \
             ( !((id_octet >> 7) & 0x01))        /* (8.1.3.5) Has next octets
                                                              lenght */
#define ASN1_BER_IS_INDEFINITE_LEN(id_octet)   \
             (id_octet == 0x80)                /* (8.1.3.6) Need end-of-ccontent */
#define ASN1_BER_IS_EOC(tmp_iter) (*tmp_iter == 0 && *(tmp_iter + 1) == 0)

/* Return the current node/frame that we are filling */
#define ASN1CTX_CUR_NODE(ac) (ac->asn1_stack[ac->cur_frame])
#define ASN1CTX_GET_NODE(ac, node) (ac->asn1_stack[node])

/* BER Universal tags */
#define ASN1_UNITAG_EOC                  0   /* EOC */
#define ASN1_UNITAG_BOOLEAN              1
#define ASN1_UNITAG_INTEGER              2
#define ASN1_UNITAG_BIT_STRING           3
#define ASN1_UNITAG_OCTET_STRING         4
#define ASN1_UNITAG_NULL                 5
#define ASN1_UNITAG_OID                  6
#define ASN1_UNITAG_OBJECT_DESCRIPTOR    7
#define ASN1_UNITAG_EXTERNAL             8
#define ASN1_UNITAG_REAL                 9
#define ASN1_UNITAG_ENUMERATED           10
#define ASN1_UNITAG_EMBEDDED_PDV         11
#define ASN1_UNITAG_UTF8_STRING          12
#define ASN1_UNITAG_RELATIVE_OID         13
#define ASN1_UNITAG_SEQUENCE             16
#define ASN1_UNITAG_SET                  17
#define ASN1_UNITAG_NUMERIC_STRING       18
#define ASN1_UNITAG_PRINTABLE_STRING     19
#define ASN1_UNITAG_TELETEX_STRING       20
#define ASN1_UNITAG_VIDEOTEX_STRING      21
#define ASN1_UNITAG_IA5_STRING           22
#define ASN1_UNITAG_UTCTIME              23
#define ASN1_UNITAG_GENERALIZED_TIME     24
#define ASN1_UNITAG_GRAPHIC_STRING       25
#define ASN1_UNITAG_VISIBLE_STRING       26
#define ASN1_UNITAG_GENERAL_STRING       27
#define ASN1_UNITAG_UNIVERSAL_STRING     28
#define ASN1_UNITAG_CHARACTER_STRING     29
#define ASN1_UNITAG_BMP_STRING           30

/* Length form */
#define ASN1_BER_LEN_SHORT          0
#define ASN1_BER_LEN_LONG           1
#define ASN1_BER_LEN_INDEFINITE     2


/* Error events/flags */
#define ASN1_BER_EVENT_ID_TOO_LONG            0x01
#define ASN1_BER_EVENT_INVALID_ID             0x02 /* (8.1.2.4.2c) First subsequent
                                                      id val (from bit 7 to 0) Shall
                                                      not be 0 */
#define ASN1_BER_EVENT_INVALID_LEN            0x04 /* (8.1.3.2a) we expect a simple
                                                      form, or (8.1.3.5c) we got
                                                      0xFF, or not enough data */
#define ASN1_BER_EVENT_LEN_TOO_LONG           0x08
#define ASN1_BER_EVENT_EOC_NOT_FOUND          0x10 /* EOC not found */


/* Helper flags */
#define ASN1_NODE_IS_EOC 1
#define ASN1_TAG_TYPE_PRIMITIVE 0
#define ASN1_TAG_TYPE_CONSTRUCTED 1

typedef struct Asn1Len_ {
    uint8_t form;
    uint32_t len;
    uint8_t *ptr;
} Asn1Len;

typedef struct Asn1Id_ {
    uint8_t *ptr;
    uint8_t class_tag;
    uint8_t tag_type;
    uint32_t tag_num;
} Asn1Id;

typedef struct Asn1Data_ {
    uint8_t *ptr;
    uint32_t len;
    uint8_t type;
} Asn1Data;

typedef struct Asn1Node_ {
    uint8_t *raw_str;
    uint8_t data_len;
    Asn1Len len;
    Asn1Id id;
    Asn1Data data;
    uint8_t flags;
} Asn1Node;

typedef struct Asn1Ctx_ {
    uint8_t *data;
    uint8_t *end;
    uint16_t len;

    uint8_t *iter;

    uint16_t cur_frame;
    Asn1Node *asn1_stack2[ASN1_MAX_FRAMES];
    Asn1Node **asn1_stack;

    uint8_t parser_status;

    uint8_t ctx_flags;
} Asn1Ctx;

/* Return codes of the decoder */
#define ASN1_PARSER_OK          0x01 /* Everything ok */
#define ASN1_PARSER_ERR         0x02 /* Internal error, fatal error, we can't continue decoding */

/* Status of the parser  */
#define ASN1_STATUS_OK          0x00 /* On the road */
#define ASN1_STATUS_INVALID     0x01 /* We found something weird/invalid by the specification, but we can try to continue parsing */
#define ASN1_STATUS_OOB         0x02 /* We don't have enough data or ran out of bounds */
#define ASN1_STATUS_DONE        0x04 /* We have finished cleanly */

void SCPrintByteBin(uint8_t);

Asn1Ctx *SCAsn1CtxNew(void);
void SCAsn1CtxInit(Asn1Ctx *, uint8_t *, uint16_t);
void SCAsn1CtxDestroy(Asn1Ctx *);

uint8_t SCAsn1Decode(Asn1Ctx *, uint16_t);
uint8_t SCAsn1DecodeIdentifier(Asn1Ctx *);
uint8_t SCAsn1DecodeLength(Asn1Ctx *);
uint8_t SCAsn1DecodeContent(Asn1Ctx *);

uint8_t SCAsn1CheckBounds(Asn1Ctx *);

void DecodeAsn1RegisterTests(void);
void SCAsn1LoadConfig();

#endif /* __DECODE_ASN1_H__ */

