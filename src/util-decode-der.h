/*
 * Copyright (C) 2011-2012 ANSSI
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *
 * \author Pierre Chifflier <pierre.chifflier@ssi.gouv.fr>
 *
 */

#ifndef __UTIL_DECODE_DER_H__
#define __UTIL_DECODE_DER_H__

#define ASN1_CLASS_UNIVERSAL   0
#define ASN1_CLASS_APPLICATION 1
#define ASN1_CLASS_CONTEXTSPEC 2
#define ASN1_CLASS_PRIVATE     3

#define ASN1_UNKNOWN        0
#define ASN1_BOOLEAN     0x01
#define ASN1_INTEGER     0x02
#define ASN1_BITSTRING   0x03
#define ASN1_OCTETSTRING 0x04
#define ASN1_NULL        0x05
#define ASN1_OID         0x06
#define ASN1_UTF8STRING  0x0c
#define ASN1_SEQUENCE    0x10
#define ASN1_SET         0x11
#define ASN1_PRINTSTRING 0x13
#define ASN1_T61STRING   0x14
#define ASN1_IA5STRING   0x16
#define ASN1_UTCTIME     0x17

typedef struct Asn1ElementType_ {
	uint8_t cls:2;
	uint8_t pc:1;
	uint8_t tag:5;
} __attribute__((packed)) Asn1ElementType;

/* Generic ASN.1 element
 * Presence and meaning of fields depends on the header and type values.
 */
typedef struct Asn1Generic_ {
	Asn1ElementType header;
	uint8_t type;
	uint32_t length; /* length of node, including header */

	struct Asn1Generic_ *data; /* only if type is structured */

	char *str;
	uint32_t strlen;
	uint64_t value;
	struct Asn1Generic_ *next; /* only if type is sequence */
} Asn1Generic;

/* Generic error */
#define ERR_DER_GENERIC               0x01
/* Unknown ASN.1 element type */
#define ERR_DER_UNKNOWN_ELEMENT       0x02
/* One element requires to read more bytes than available */
#define ERR_DER_ELEMENT_SIZE_TOO_BIG  0x03
/* One element size is invalid (more than 4 bytes long) */
#define ERR_DER_INVALID_SIZE          0x04
/* Unsupported string type */
#define ERR_DER_UNSUPPORTED_STRING    0x05
/* Missing field or element */
#define ERR_DER_MISSING_ELEMENT       0x06

Asn1Generic * DecodeDer(const unsigned char *buffer, uint32_t size, uint32_t *errcode);
void DerFree(Asn1Generic *a);

#endif /* __UTIL_DECODE_DER_H__ */
