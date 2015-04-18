/*
 * Copyright (C) 2011-2015 ANSSI
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

/*
 * An ASN.1 Parser for DER-encoded structures.
 * This parser is not written to be complete or fast, but is rather
 * focused on stability and security.
 * It does not support all ASN.1 structure, only a meaningful subset
 * to decode x509v3 certificates (See RFC 3280).
 *
 * References (like 8.19.4) are relative to the ISO/IEC 8825-1:2003 document
 *
 */

#include "suricata-common.h"

#include "util-decode-der.h"

#define MAX_OID_LENGTH 256

static Asn1Generic * DecodeAsn1DerBitstring(const unsigned char *buffer, uint32_t size, uint8_t depth, uint32_t *errcode);
static Asn1Generic * DecodeAsn1DerBoolean(const unsigned char *buffer, uint32_t size, uint8_t depth, uint32_t *errcode);
static Asn1Generic * DecodeAsn1DerIA5String(const unsigned char *buffer, uint32_t size, uint8_t depth, uint32_t *errcode);
static Asn1Generic * DecodeAsn1DerInteger(const unsigned char *buffer, uint32_t size, uint8_t depth, uint32_t *errcode);
static Asn1Generic * DecodeAsn1DerNull(const unsigned char *buffer, uint32_t size, uint8_t depth, uint32_t *errcode);
static Asn1Generic * DecodeAsn1DerOctetString(const unsigned char *buffer, uint32_t size, uint8_t depth, uint32_t *errcode);
static Asn1Generic * DecodeAsn1DerUTF8String(const unsigned char *buffer, uint32_t max_size, uint8_t depth, uint32_t *errcode);
static Asn1Generic * DecodeAsn1DerOid(const unsigned char *buffer, uint32_t size, uint8_t depth, uint32_t *errcode);
static Asn1Generic * DecodeAsn1DerPrintableString(const unsigned char *buffer, uint32_t size, uint8_t depth, uint32_t *errcode);
static Asn1Generic * DecodeAsn1DerSequence(const unsigned char *buffer, uint32_t size, uint8_t depth, uint32_t *errcode);
static Asn1Generic * DecodeAsn1DerSet(const unsigned char *buffer, uint32_t size, uint8_t depth, uint32_t *errcode);
static Asn1Generic * DecodeAsn1DerT61String(const unsigned char *buffer, uint32_t size, uint8_t depth, uint32_t *errcode);
static Asn1Generic * DecodeAsn1DerUTCTime(const unsigned char *buffer, uint32_t size, uint8_t depth, uint32_t *errcode);

static Asn1Generic * Asn1GenericNew(void)
{
    Asn1Generic *obj;

    obj = SCMalloc(sizeof(Asn1Generic));
    if (obj != NULL)
        memset(obj, 0, sizeof(Asn1Generic));

    return obj;
}

/**
 * \retval r 0 ok, -1 error
 */
static int Asn1SequenceAppend(Asn1Generic *seq, Asn1Generic *node)
{
    Asn1Generic *it, *new_container;

    if (seq->data == NULL) {
        seq->data = node;
        return 0;
    }

    new_container = Asn1GenericNew();
    if (new_container == NULL)
        return -1;
    new_container->data = node;

    for (it=seq; it->next != NULL; it=it->next)
        ;

    it->next = new_container;
    return 0;
}

static Asn1Generic * DecodeAsn1DerGeneric(const unsigned char *buffer, uint32_t max_size, uint8_t depth, int seq_index, uint32_t *errcode)
{
    const unsigned char *d_ptr = buffer;
    uint32_t numbytes, el_max_size;
    Asn1ElementType el;
    uint8_t c;
    uint32_t i;
    Asn1Generic *child;
    uint8_t el_type;

    el.cls = (d_ptr[0] & 0xc0) >> 6;
    el.pc = (d_ptr[0] & 0x20) >> 5;
    el.tag = (d_ptr[0] & 0x1f);

    el_type = el.tag;

    if (el.tag == 0x1f)
        return NULL;

    switch (el.cls) {
        case ASN1_CLASS_CONTEXTSPEC:
            /* get element type from definition
             * see http://www.ietf.org/rfc/rfc3280.txt)
             */
            if (depth == 2 && el.tag == 0) {
                el_type = ASN1_SEQUENCE; /* TBSCertificate */
                break;
            }
            if (depth == 2 && el.tag == 1) {
                el_type = ASN1_BITSTRING; /* issuerUniqueID */
                break;
            }
            if (depth == 2 && el.tag == 2) {
                el_type = ASN1_BITSTRING; /* subjectUniqueID */
                break;
            }
            if (depth == 2 && el.tag == 3) {
                el_type = ASN1_SEQUENCE; /* extensions */
                break;
            }
            /* unknown context specific value - do not decode */
            break;
    };

    el_max_size = max_size - (d_ptr-buffer);
    switch (el_type) {
        case ASN1_INTEGER:
            child = DecodeAsn1DerInteger(d_ptr, el_max_size, depth+1, errcode);
            break;
        case ASN1_BOOLEAN:
            child = DecodeAsn1DerBoolean(d_ptr, el_max_size, depth+1, errcode);
            break;
        case ASN1_NULL:
            child = DecodeAsn1DerNull(d_ptr, el_max_size, depth+1, errcode);
            break;
        case ASN1_BITSTRING:
            child = DecodeAsn1DerBitstring(d_ptr, el_max_size, depth+1, errcode);
            break;
        case ASN1_OID:
            child = DecodeAsn1DerOid(d_ptr, el_max_size, depth+1, errcode);
            break;
        case ASN1_IA5STRING:
            child = DecodeAsn1DerIA5String(d_ptr, el_max_size, depth+1, errcode);
            break;
        case ASN1_OCTETSTRING:
            child = DecodeAsn1DerOctetString(d_ptr, el_max_size, depth+1, errcode);
            break;
        case ASN1_UTF8STRING:
            child = DecodeAsn1DerUTF8String(d_ptr, el_max_size, depth+1, errcode);
            break;
        case ASN1_PRINTSTRING:
            child = DecodeAsn1DerPrintableString(d_ptr, el_max_size, depth+1, errcode);
            break;
        case ASN1_SEQUENCE:
            child = DecodeAsn1DerSequence(d_ptr, el_max_size, depth+1, errcode);
            break;
        case ASN1_SET:
            child = DecodeAsn1DerSet(d_ptr, el_max_size, depth+1, errcode);
            break;
        case ASN1_T61STRING:
            child = DecodeAsn1DerT61String(d_ptr, el_max_size, depth+1, errcode);
            break;
        case ASN1_UTCTIME:
            child = DecodeAsn1DerUTCTime(d_ptr, el_max_size, depth+1, errcode);
            break;
        default:
            /* unknown ASN.1 type */
            child = NULL;
            child = Asn1GenericNew();
            if (child == NULL)
                break;
            child->type = el.tag;
            /* total sequence length */
            const unsigned char * save_d_ptr = d_ptr;
            d_ptr++;
            c = d_ptr[0];
            if ((c & (1<<7))>>7 == 0) { /* short form 8.1.3.4 */
                child->length = c;
                d_ptr++;
            } else { /* long form 8.1.3.5 */
                numbytes = c & 0x7f;
                if (numbytes > el_max_size) {
                    SCFree(child);
                    if (errcode)
                        *errcode = ERR_DER_ELEMENT_SIZE_TOO_BIG;
                    return NULL;
                }
                child->length = 0;
                d_ptr++;
                for (i=0; i<numbytes; i++) {
                    child->length = child->length<<8 | d_ptr[0];
                    d_ptr++;
                }
            }
            /* fix the length for unknown objects, else
             * sequence parsing will fail
             */
            child->length += (d_ptr - save_d_ptr);
            break;
    };
    if (child == NULL)
        return NULL;

    child->header = el;
    return child;
}

static Asn1Generic * DecodeAsn1DerInteger(const unsigned char *buffer, uint32_t size, uint8_t depth, uint32_t *errcode)
{
    const unsigned char *d_ptr = buffer;
    uint8_t numbytes;
    uint32_t value;
    uint32_t i;
    Asn1Generic *a;

    numbytes = d_ptr[1];

    if (numbytes > size) {
        if (errcode)
            *errcode = ERR_DER_ELEMENT_SIZE_TOO_BIG;
        return NULL;
    }

    d_ptr += 2;

    value = 0;
    /* Here we need to ensure that numbytes is less than 4
       so integer affectation is possible. We set the value
       to 0xffffffff which is by convention the unknown value.
       In this case, the hexadecimal value must be used. */
    if (numbytes > 4) {
        value = 0xffffffff;
    } else {
        for (i=0; i<numbytes; i++) {
            value = value<<8 | d_ptr[i];
        }
    }

    a = Asn1GenericNew();
    if (a == NULL)
        return NULL;
    a->type = ASN1_INTEGER;
    a->length = (d_ptr - buffer) + numbytes;
    a->value = value;

    a->str = SCMalloc(2*numbytes + 1);
    if (a->str == NULL) {
        SCFree(a);
        return NULL;
    }
    for (i=0; i<numbytes; i++) {
        snprintf(a->str + 2*i, 2*(numbytes-i)+1, "%02X", d_ptr[i]);
    }
    a->str[2*numbytes]='\0';

    return a;
}

static int DecodeAsn1BuildValue(const unsigned char **d_ptr, uint32_t *val, uint8_t numbytes, uint32_t *errcode)
{
    int i;
    uint32_t value = 0;
    if (numbytes > 4) {
        if (errcode)
            *errcode = ERR_DER_INVALID_SIZE;
        /* too big won't fit: set it to 0xffffffff by convention */
        value = 0xffffffff;
        *val = value;
        return -1;
    } else {
        for (i=0; i<numbytes; i++) {
            value = value<<8 | (*d_ptr)[0];
            (*d_ptr)++;
        }
    }
    *val = value;
    return 0;
}

static Asn1Generic * DecodeAsn1DerBoolean(const unsigned char *buffer, uint32_t size, uint8_t depth, uint32_t *errcode)
{
    const unsigned char *d_ptr = buffer;
    uint8_t numbytes;
    uint32_t value;
    Asn1Generic *a;

    numbytes = d_ptr[1];
    d_ptr += 2;

    if (DecodeAsn1BuildValue(&d_ptr, &value, numbytes, errcode) == -1) {
        return NULL;
    }
    a = Asn1GenericNew();
    if (a == NULL)
        return NULL;
    a->type = ASN1_BOOLEAN;
    a->length = (d_ptr - buffer);
    a->value = value;

    return a;
}

static Asn1Generic * DecodeAsn1DerNull(const unsigned char *buffer, uint32_t size, uint8_t depth, uint32_t *errcode)
{
    const unsigned char *d_ptr = buffer;
    uint8_t numbytes;
    uint32_t value;
    Asn1Generic *a;

    numbytes = d_ptr[1];
    d_ptr += 2;
    if (DecodeAsn1BuildValue(&d_ptr, &value, numbytes, errcode) == -1) {
        return NULL;
    }
    a = Asn1GenericNew();
    if (a == NULL)
        return NULL;
    a->type = ASN1_NULL;
    a->length = (d_ptr - buffer);
    a->value = 0;

    return a;
}

static Asn1Generic * DecodeAsn1DerBitstring(const unsigned char *buffer, uint32_t max_size, uint8_t depth, uint32_t *errcode)
{
    const unsigned char *d_ptr = buffer;
    uint32_t length;
    uint8_t numbytes, c;
    Asn1Generic *a;

    d_ptr++;

    /* size */
    c = d_ptr[0];
    if ((c & (1<<7))>>7 == 0) { /* short form 8.1.3.4 */
        length = c;
        d_ptr++;
    } else { /* long form 8.1.3.5 */
        numbytes = c & 0x7f;
        d_ptr++;
        if (DecodeAsn1BuildValue(&d_ptr, &length, numbytes, errcode) == -1) {
            return NULL;
        }
    }
    if (length > max_size)
        return NULL;

    a = Asn1GenericNew();
    if (a == NULL)
        return NULL;
    a->type = ASN1_BITSTRING;
    a->strlen = length;
    a->str = SCMalloc(length);
    if (a->str == NULL) {
        SCFree(a);
        return NULL;
    }
    memcpy(a->str, (const char*)d_ptr, length);

    d_ptr += length;

    a->length = (d_ptr - buffer);
    return a;
}

static Asn1Generic * DecodeAsn1DerOid(const unsigned char *buffer, uint32_t max_size, uint8_t depth, uint32_t *errcode)
{
    const unsigned char *d_ptr = buffer;
    uint32_t oid_length, oid_value;
    uint8_t numbytes, c;
    Asn1Generic *a;
    uint32_t i;

    d_ptr++;

    /* size */
    c = d_ptr[0];
    if ((c & (1<<7))>>7 == 0) { /* short form 8.1.3.4 */
        oid_length = c;
        d_ptr++;
    } else { /* long form 8.1.3.5 */
        numbytes = c & 0x7f;
        d_ptr++;
        if (DecodeAsn1BuildValue(&d_ptr, &oid_length, numbytes, errcode) == -1) {
            return NULL;
        }
    }
    if (oid_length > max_size)
        return NULL;

    a = Asn1GenericNew();
    if (a == NULL)
        return NULL;
    a->type = ASN1_OID;
    a->str = SCMalloc(MAX_OID_LENGTH);
    if (a->str == NULL) {
        SCFree(a);
        return NULL;
    }

    /* first element = X*40 + Y (See 8.19.4) */
    snprintf(a->str, MAX_OID_LENGTH, "%d.%d", (d_ptr[0]/40), (d_ptr[0]%40));
    d_ptr++;

    /* sub-identifiers are multi valued, coded and 7 bits, first bit of the 8bits is used
       to indicate, if a new value is starting */
    for (i=1; i<oid_length; ) {
        int s = strlen(a->str);
        c = d_ptr[0];
        oid_value = 0;
        while ( i<oid_length && (c & (1<<7)) == 1<<7 ) {
            oid_value = oid_value<<7 | (c & ~(1<<7));
            d_ptr++;
            c = d_ptr[0];
            i++;
        }
        oid_value = oid_value<<7 | c;
        d_ptr++;
        i++;
        snprintf(a->str + s, MAX_OID_LENGTH - s, ".%d", oid_value);
    }

    a->length = (d_ptr - buffer);
    return a;
}

static Asn1Generic * DecodeAsn1DerIA5String(const unsigned char *buffer, uint32_t max_size, uint8_t depth, uint32_t *errcode)
{
    const unsigned char *d_ptr = buffer;
    uint32_t length, numbytes;
    Asn1Generic *a;
    unsigned char c;

    d_ptr++;

    /* total sequence length */
    c = d_ptr[0];
    if ((c & (1<<7))>>7 == 0) { /* short form 8.1.3.4 */
        length = c;
        d_ptr++;
    } else { /* long form 8.1.3.5 */
        numbytes = c & 0x7f;
        d_ptr++;
        if (DecodeAsn1BuildValue(&d_ptr, &length, numbytes, errcode) == -1) {
            return NULL;
        }
    }
    if (length == UINT32_MAX || length > max_size) {
        if (errcode)
            *errcode = ERR_DER_ELEMENT_SIZE_TOO_BIG;
        return NULL;
    }

    a = Asn1GenericNew();
    if (a == NULL)
        return NULL;
    a->type = ASN1_IA5STRING;
    a->strlen = length;
    a->str = SCMalloc(length+1);
    if (a->str == NULL) {
        SCFree(a);
        return NULL;
    }
    strlcpy(a->str, (const char*)d_ptr, length+1);

    d_ptr += length;

    a->length = (d_ptr - buffer);
    return a;
}

static Asn1Generic * DecodeAsn1DerOctetString(const unsigned char *buffer, uint32_t max_size, uint8_t depth, uint32_t *errcode)
{
    const unsigned char *d_ptr = buffer;
    uint32_t length, numbytes;
    Asn1Generic *a;
    unsigned char c;

    d_ptr++;

    /* total sequence length */
    c = d_ptr[0];
    if ((c & (1<<7))>>7 == 0) { /* short form 8.1.3.4 */
        length = c;
        d_ptr++;
    } else { /* long form 8.1.3.5 */
        numbytes = c & 0x7f;
        d_ptr++;
        if (DecodeAsn1BuildValue(&d_ptr, &length, numbytes, errcode) == -1) {
            return NULL;
        }
    }
    if (length == UINT32_MAX || length > max_size) {
        if (errcode)
            *errcode = ERR_DER_ELEMENT_SIZE_TOO_BIG;
        return NULL;
    }

    a = Asn1GenericNew();
    if (a == NULL)
        return NULL;
    a->type = ASN1_OCTETSTRING;
    a->strlen = length;
    /* Add one to the octet string for the 0. This will then
     * allow us to use the string in printf */
    a->str = SCMalloc(length + 1);
    if (a->str == NULL) {
        SCFree(a);
        return NULL;
    }
    memcpy(a->str, (const char*)d_ptr, length);
    a->str[length] = 0;

    d_ptr += length;

    a->length = (d_ptr - buffer);
    return a;
}

static Asn1Generic * DecodeAsn1DerUTF8String(const unsigned char *buffer, uint32_t max_size, uint8_t depth, uint32_t *errcode)
{
    Asn1Generic *a = DecodeAsn1DerOctetString(buffer, max_size, depth, errcode);
    if (a != NULL)
        a->type = ASN1_UTF8STRING;
    return a;
}

static Asn1Generic * DecodeAsn1DerPrintableString(const unsigned char *buffer, uint32_t max_size, uint8_t depth, uint32_t *errcode)
{
    const unsigned char *d_ptr = buffer;
    uint32_t length, numbytes;
    Asn1Generic *a;
    unsigned char c;

    d_ptr++;

    /* total sequence length */
    c = d_ptr[0];
    if ((c & (1<<7))>>7 == 0) { /* short form 8.1.3.4 */
        length = c;
        d_ptr++;
    } else { /* long form 8.1.3.5 */
        numbytes = c & 0x7f;
        d_ptr++;
        if (DecodeAsn1BuildValue(&d_ptr, &length, numbytes, errcode) == -1) {
            return NULL;
        }
    }
    if (length == UINT32_MAX || length > max_size) {
        if (errcode)
            *errcode = ERR_DER_ELEMENT_SIZE_TOO_BIG;
        return NULL;
    }

    a = Asn1GenericNew();
    if (a == NULL)
        return NULL;
    a->type = ASN1_PRINTSTRING;
    a->strlen = length;
    a->str = SCMalloc(length+1);
    if (a->str == NULL) {
        SCFree(a);
        return NULL;
    }
    strlcpy(a->str, (const char*)d_ptr, length+1);
    a->str[length] = '\0';

    d_ptr += length;

    a->length = (d_ptr - buffer);
    return a;
}

static Asn1Generic * DecodeAsn1DerSequence(const unsigned char *buffer, uint32_t max_size, uint8_t depth, uint32_t *errcode)
{
    const unsigned char *d_ptr = buffer;
    uint32_t d_length, parsed_bytes, numbytes, el_max_size;
    uint8_t c;
    uint32_t seq_index;
    Asn1Generic *node;

    d_ptr++;

    node = Asn1GenericNew();
    if (node == NULL)
        return NULL;
    node->type = ASN1_SEQUENCE;

    /* total sequence length */
    c = d_ptr[0];
    if ((c & (1<<7))>>7 == 0) { /* short form 8.1.3.4 */
        d_length = c;
        d_ptr++;
    } else { /* long form 8.1.3.5 */
        numbytes = c & 0x7f;
        d_ptr++;
        if (DecodeAsn1BuildValue(&d_ptr, &d_length, numbytes, errcode) == -1) {
            SCFree(node);
            return NULL;
        }
    }
    node->length = d_length + (d_ptr - buffer);
    if (node->length > max_size || node->length < d_length /* wrap */) {
        if (errcode)
            *errcode = ERR_DER_ELEMENT_SIZE_TOO_BIG;
        SCFree(node);
        return NULL;
    }

    parsed_bytes = 0;
    seq_index = 0;

    /* decode child elements */
    while (parsed_bytes < d_length) {
        el_max_size = max_size - (d_ptr-buffer);

        Asn1Generic *child = DecodeAsn1DerGeneric(d_ptr, el_max_size, depth, seq_index, errcode);
        if (child == NULL) {
            if (errcode && *errcode != 0) {
                DerFree(node);
                return NULL;
            }
            break;
        }

        int ret = Asn1SequenceAppend(node, child);
        if (ret == -1) {
            DerFree(child);
            break;
        }

        parsed_bytes += child->length;
        d_ptr += child->length;
        seq_index++;

    }

    return (Asn1Generic *)node;
}

static Asn1Generic * DecodeAsn1DerSet(const unsigned char *buffer, uint32_t max_size, uint8_t depth, uint32_t *errcode)
{
    const unsigned char *d_ptr = buffer;
    uint32_t d_length, numbytes, el_max_size;
    uint8_t c;
    uint32_t seq_index;
    Asn1Generic *node;
    Asn1Generic *child;

    d_ptr++;

    node = Asn1GenericNew();
    if (node == NULL)
        return NULL;
    node->type = ASN1_SET;
    node->data = NULL;

    /* total sequence length */
    c = d_ptr[0];
    if ((c & (1<<7))>>7 == 0) { /* short form 8.1.3.4 */
        d_length = c;
        d_ptr++;
    } else { /* long form 8.1.3.5 */
        numbytes = c & 0x7f;
        d_ptr++;
        if (DecodeAsn1BuildValue(&d_ptr, &d_length, numbytes, errcode) == -1) {
            SCFree(node);
            return NULL;
        }
    }
    node->length = d_length + (d_ptr - buffer);

    if (node->length > max_size || node->length < d_length /* wrap */) {
        if (errcode)
            *errcode = ERR_DER_ELEMENT_SIZE_TOO_BIG;
        SCFree(node);
        return NULL;
    }

    seq_index = 0;

    el_max_size = max_size - (d_ptr-buffer);
    child = DecodeAsn1DerGeneric(d_ptr, el_max_size, depth, seq_index, errcode);
    if (child == NULL) {
        DerFree(node);
        return NULL;
    }

    node->data = child;

    return (Asn1Generic *)node;
}

static Asn1Generic * DecodeAsn1DerT61String(const unsigned char *buffer, uint32_t max_size, uint8_t depth, uint32_t *errcode)
{
    Asn1Generic *a;

    a = DecodeAsn1DerIA5String(buffer, max_size, depth, errcode);
    if (a != NULL)
        a->type = ASN1_T61STRING;

    return a;
}

static Asn1Generic * DecodeAsn1DerUTCTime(const unsigned char *buffer, uint32_t max_size, uint8_t depth, uint32_t *errcode)
{
    Asn1Generic *a;

    a = DecodeAsn1DerIA5String(buffer, max_size, depth, errcode);
    if (a != NULL)
        a->type = ASN1_UTCTIME;

    return a;
}

Asn1Generic * DecodeDer(const unsigned char *buffer, uint32_t size, uint32_t *errcode)
{
    const unsigned char *d_ptr = buffer;
    uint32_t d_length, numbytes;
    Asn1Generic *cert;
    uint8_t c;

    /* Check that buffer is an ASN.1 structure (basic checks) */
    if (d_ptr[0] != 0x30 && d_ptr[1] != 0x82) /* Sequence */
        return NULL;

    c = d_ptr[1];
    if ((c & (1<<7))>>7 != 1)
        return NULL;

    numbytes = c & 0x7f;
    d_ptr += 2;
    if (DecodeAsn1BuildValue(&d_ptr, &d_length, numbytes, errcode) == -1) {
        return NULL;
    }
    if (d_length+(d_ptr-buffer) != size)
        return NULL;

    if (errcode)
        *errcode = 0;

    cert = DecodeAsn1DerGeneric(buffer, size, 0 /* depth */, 0, errcode);

    return cert;
}

void DerFree(Asn1Generic *a)
{
    Asn1Generic *it, *n;

    if (a == NULL)
        return;

    it = a;
    while (it) {
        n = it->next;
        if (it->data) {
            DerFree(it->data);
        }
        if (it->str)
            SCFree(it->str);
        memset(it, 0xff, sizeof(Asn1Generic));
        SCFree(it);
        it = n;
    }
}
