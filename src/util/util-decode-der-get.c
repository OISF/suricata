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

#include "suricata-common.h"

#include "util-decode-der.h"
#include "util-decode-der-get.h"

static const uint8_t SEQ_IDX_SERIAL[] = { 0, 0 };
static const uint8_t SEQ_IDX_ISSUER[] = { 0, 2 };
static const uint8_t SEQ_IDX_VALIDITY[] = { 0, 3 };
static const uint8_t SEQ_IDX_SUBJECT[] = { 0, 4 };

static const char *Oid2ShortStr(const char *oid)
{
    if (strcmp(oid, "1.2.840.113549.1.9.1") == 0)
        return "emailAddress";

    if (strcmp(oid, "2.5.4.3") == 0)
        return "CN";

    if (strcmp(oid, "2.5.4.5") == 0)
        return "serialNumber";

    if (strcmp(oid, "2.5.4.6") == 0)
        return "C";

    if (strcmp(oid, "2.5.4.7") == 0)
        return "L";

    if (strcmp(oid, "2.5.4.8") == 0)
        return "ST";

    if (strcmp(oid, "2.5.4.10") == 0)
        return "O";

    if (strcmp(oid, "2.5.4.11") == 0)
        return "OU";

    if (strcmp(oid, "0.9.2342.19200300.100.1.25") == 0)
        return "DC";

    return "unknown";
}

static time_t GentimeToTime(char *gentime)
{
    time_t time;
    struct tm tm;

    /* GeneralizedTime values MUST be expressed in Greenwich Mean Time
     * (Zulu) and MUST include seconds (rfc5280 4.1.2.5.2). It MUST NOT
     * include fractional seconds. It should therefore be on the format
     * YYYYmmddHHMMSSZ. */
    if (strlen(gentime) != 15)
        goto error;

    memset(&tm, 0, sizeof(tm));
    strptime(gentime, "%Y%m%d%H%M%SZ", &tm);
    time = SCMkTimeUtc(&tm);

    if (time < 0)
        goto error;

    return time;

error:
    return -1;
}

static time_t UtctimeToTime(char *utctime)
{
    time_t time;
    unsigned int year;
    char yy[3];
    char buf[20];

    /* UTCTime values MUST be expressed in Greenwich Mean Time (Zulu)
     * and MUST include seconds (rfc5280 4.1.2.5.1). It should
     * therefore be on the format YYmmddHHMMSSZ. */
    if (strlen(utctime) != 13)
        goto error;

    /* UTCTime use two digits to represent the year. The year field (YY)
     * should be interpreted as 19YY when it is greater than or equal to
     * 50. If it is less than 50 it should be interpreted as 20YY.
     * Because of this, GeneralizedTime must be used for dates in the
     * year 2050 or later. */
    strlcpy(yy, utctime, sizeof(yy));
    year = strtol(yy, NULL, 10);
    if (year >= 50)
        snprintf(buf, sizeof(buf), "%i%s", 19, utctime);
    else
        snprintf(buf, sizeof(buf), "%i%s", 20, utctime);

    time = GentimeToTime(buf);
    if (time == -1)
        goto error;

    return time;

error:
    return -1;
}

/**
 * \brief Iterate through an ASN.1 structure, following the index sequence.
 *        Context specific elements are skipped.
 *
 * \retval The matching node, or NULL
 */
const Asn1Generic * Asn1DerGet(const Asn1Generic *top, const uint8_t *seq_index,
                               const uint32_t seqsz, uint32_t *errcode)
{
    const Asn1Generic * node;
    uint8_t idx, i;
    uint8_t offset = 0;

    if (errcode)
        *errcode = ERR_DER_MISSING_ELEMENT;

    node = top;
    if (node == NULL || seq_index == NULL)
        return NULL;

    for (offset=0; offset<seqsz; offset++) {

        idx = seq_index[offset];
        for (i=0; i<idx; i++) {
            if (node == NULL || node->data == NULL)
                return NULL;

            /* skip context-specific elements */
            while (node->data->header.cls == ASN1_CLASS_CONTEXTSPEC) {
                node = node->next;
                if (node == NULL || node->data == NULL)
                    return NULL;
            }

            node = node->next;
            if (node == NULL || node->data == NULL)
                return NULL;
        }

        /* skip context-specific elements */
        if (node == NULL || node->data == NULL)
            return NULL;
        while (node->data->header.cls == ASN1_CLASS_CONTEXTSPEC) {
            node = node->next;
            if (node == NULL || node->data == NULL)
                return NULL;
        }

        node = node->data;
    }

    if (errcode)
        *errcode = 0;

    return node;
}

int Asn1DerGetValidity(const Asn1Generic *cert, time_t *not_before,
                       time_t *not_after, uint32_t *errcode)
{
    const Asn1Generic *node, *it;
    int rc = -1;

    if (errcode)
        *errcode = ERR_DER_MISSING_ELEMENT;

    node = Asn1DerGet(cert, SEQ_IDX_VALIDITY, sizeof(SEQ_IDX_VALIDITY), errcode);
    if ((node == NULL) || node->type != ASN1_SEQUENCE)
        goto validity_error;

    it = node->data;
    if (it == NULL || it->str == NULL)
        goto validity_error;

    if (it->type == ASN1_UTCTIME)
        *not_before = UtctimeToTime(it->str);
    else if (it->type == ASN1_GENERALIZEDTIME)
        *not_before = GentimeToTime(it->str);
    else
        goto validity_error;

    if (*not_before == -1)
        goto validity_error;

    if (node->next == NULL)
        goto validity_error;

    it = node->next->data;

    if (it == NULL || it->str == NULL)
        goto validity_error;

    if (it->type == ASN1_UTCTIME)
        *not_after = UtctimeToTime(it->str);
    else if (it->type == ASN1_GENERALIZEDTIME)
        *not_after = GentimeToTime(it->str);
    else
        goto validity_error;

    if (*not_after == -1)
        goto validity_error;

    rc = 0;

validity_error:
    return rc;
}

int Asn1DerGetSerial(const Asn1Generic *cert, char *buffer, uint32_t length,
                       uint32_t *errcode)
{
    const Asn1Generic *node;
    uint32_t node_len, i;
    int rc = -1;

    if (errcode)
        *errcode = ERR_DER_MISSING_ELEMENT;

    buffer[0] = '\0';

    node = Asn1DerGet(cert, SEQ_IDX_SERIAL, sizeof(SEQ_IDX_SERIAL), errcode);
    if ((node == NULL) || node->type != ASN1_INTEGER || node->str == NULL)
        goto serial_error;

    node_len = strlen(node->str);

    /* make sure the buffer is big enough */
    if (node_len + (node_len / 2) > length)
        goto serial_error;

    /* format serial number (e.g. XX:XX:XX:XX:XX) */
    for (i = 0; i < node_len; i++) {
        char c[3];
        /* insert separator before each even number */
        if (((i % 2) == 0) && (i != 0)) {
            snprintf(c, sizeof(c), ":%c", node->str[i]);
        } else {
            snprintf(c, sizeof(c), "%c", node->str[i]);
        }

        strlcat(buffer, c, length);
    }

    if (errcode)
        *errcode = 0;

    rc = 0;

serial_error:
    return rc;
}

int Asn1DerGetIssuerDN(const Asn1Generic *cert, char *buffer, uint32_t length,
                       uint32_t *errcode)
{
    const Asn1Generic *node_oid;
    const Asn1Generic *node;
    const Asn1Generic *it;
    const Asn1Generic *node_set;
    const Asn1Generic *node_str;
    const char *shortname;
    int rc = -1;
    const char *separator = ", ";

    if (errcode)
        *errcode = ERR_DER_MISSING_ELEMENT;

    if (length < 10)
        goto issuer_dn_error;

    buffer[0] = '\0';

    node = Asn1DerGet(cert, SEQ_IDX_ISSUER, sizeof(SEQ_IDX_ISSUER), errcode);
    if ((node == NULL) || node->type != ASN1_SEQUENCE)
        goto issuer_dn_error;

    it = node;
    while (it != NULL) {
        if (it->data == NULL)
            goto issuer_dn_error;
        node_set = it->data;
        if (node_set->type != ASN1_SET || node_set->data == NULL)
            goto issuer_dn_error;
        node = node_set->data;
        if (node->type != ASN1_SEQUENCE || node->data == NULL)
            goto issuer_dn_error;
        node_oid = node->data;
        if (node_oid->str == NULL || node_oid->type != ASN1_OID)
            goto issuer_dn_error;
        shortname = Oid2ShortStr(node_oid->str);
        if (node->next == NULL)
            goto issuer_dn_error;
        node = node->next;
        node_str = node->data;
        if (node_str == NULL || node_str->str == NULL)
            goto issuer_dn_error;

        switch (node_str->type) {
            case ASN1_PRINTSTRING:
            case ASN1_IA5STRING:
            case ASN1_T61STRING:
            case ASN1_UTF8STRING:
            case ASN1_OCTETSTRING:
                strlcat(buffer, shortname, length);
                strlcat(buffer, "=", length);
                strlcat(buffer, node_str->str, length);
                break;
            default:
                if (errcode)
                    *errcode = ERR_DER_UNSUPPORTED_STRING;
                goto issuer_dn_error;
        }

        if (strcmp(shortname,"CN") == 0)
            separator = "/";
        if (it->next != NULL)
            strlcat(buffer, separator, length);
        it = it->next;
    }

    if (errcode)
        *errcode = 0;

    rc = 0;
issuer_dn_error:
    return rc;
}

int Asn1DerGetSubjectDN(const Asn1Generic *cert, char *buffer, uint32_t length,
                        uint32_t *errcode)
{
    const Asn1Generic *node_oid;
    const Asn1Generic *node;
    const Asn1Generic *it;
    const Asn1Generic *node_set;
    const Asn1Generic *node_str;
    const char *shortname;
    int rc = -1;
    const char *separator = ", ";

    if (errcode)
        *errcode = ERR_DER_MISSING_ELEMENT;

    if (length < 10)
        goto subject_dn_error;

    buffer[0] = '\0';

    node = Asn1DerGet(cert, SEQ_IDX_SUBJECT, sizeof(SEQ_IDX_SUBJECT), errcode);

    if ((node == NULL) || node->type != ASN1_SEQUENCE)
        goto subject_dn_error;

    it = node;
    while (it != NULL) {
        if (it == NULL || it->data == NULL)
            goto subject_dn_error;
        node_set = it->data;
        if (node_set->type != ASN1_SET || node_set->data == NULL)
            goto subject_dn_error;
        node = node_set->data;
        if (node->type != ASN1_SEQUENCE || node->data == NULL)
            goto subject_dn_error;
        node_oid = node->data;
        if (node_oid->str == NULL || node_oid->type != ASN1_OID)
            goto subject_dn_error;
        shortname = Oid2ShortStr(node_oid->str);
        if (node->next == NULL)
            goto subject_dn_error;
        node = node->next;
        node_str = node->data;
        if (node_str == NULL || node_str->str == NULL)
            goto subject_dn_error;

        switch (node_str->type) {
            case ASN1_PRINTSTRING:
            case ASN1_IA5STRING:
            case ASN1_T61STRING:
            case ASN1_UTF8STRING:
            case ASN1_OCTETSTRING:
                strlcat(buffer, shortname, length);
                strlcat(buffer, "=", length);
                strlcat(buffer, node_str->str, length);
                break;
            default:
                if (errcode)
                    *errcode = ERR_DER_UNSUPPORTED_STRING;
                goto subject_dn_error;
        }

        if (strcmp(shortname,"CN") == 0)
            separator = "/";
        if (it->next != NULL)
            strlcat(buffer, separator, length);
        it = it->next;
    }

    if (errcode)
        *errcode = 0;

    rc = 0;
subject_dn_error:
    return rc;
}

