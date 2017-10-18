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
#include "app-layer-ssl.h"

#include "util-decode-der.h"
#include "util-decode-der-get.h"

/* number of extensions supported */
#define EXTN_MAX 15

typedef struct AsnExtension_ {
    const char *extn_id;
    const char *extn_name;
#ifdef HAVE_LIBJANSSON
    json_t *(*ExtnGetValueAsJson)(SSLCertExtension *);
#endif
} AsnExtension;

static const uint8_t SEQ_IDX_SERIAL[] = { 0, 0 };
static const uint8_t SEQ_IDX_CERT_SIGNATURE_ALGO[] = { 0, 1 };
static const uint8_t SEQ_IDX_ISSUER[] = { 0, 2 };
static const uint8_t SEQ_IDX_VALIDITY[] = { 0, 3 };
static const uint8_t SEQ_IDX_SUBJECT[] = { 0, 4 };
static const uint8_t SEQ_IDX_SUBJECT_PK[] = { 0, 5 };
static const uint8_t SEQ_IDX_SIGNATURE_ALGO[] = { 1, 0 };

static AsnExtension asn_extns[EXTN_MAX] = {
    { .extn_id = "2.5.29.19", .extn_name = "basic_contraints",
#ifdef HAVE_LIBJANSSON
        NULL
#endif
    },
    { .extn_id = "2.5.29.30", .extn_name = "name_contraints",
#ifdef HAVE_LIBJANSSON
        NULL
#endif
    },
    { .extn_id = "2.5.29.36", .extn_name = "policy_contraints",
#ifdef HAVE_LIBJANSSON
        NULL
#endif
    },
    { .extn_id = "2.5.29.15", .extn_name = "key_usage",
#ifdef HAVE_LIBJANSSON
        NULL
#endif
    },
    { .extn_id = "2.5.29.37", .extn_name = "extended_key_usage",
#ifdef HAVE_LIBJANSSON
        NULL
#endif
    },
    { .extn_id = "2.5.29.14", .extn_name = "subject_key_identifier",
#ifdef HAVE_LIBJANSSON
        NULL
#endif
    },
    { .extn_id = "2.5.29.35", .extn_name = "authority_key_identifier",
#ifdef HAVE_LIBJANSSON
        NULL
#endif
    },
    { .extn_id = "2.5.29.17", .extn_name = "subject_alternative_name",
#ifdef HAVE_LIBJANSSON
        NULL
#endif
    },
    { .extn_id = "2.5.29.18", .extn_name = "issuer_alternative_name",
#ifdef HAVE_LIBJANSSON
        NULL
#endif
    },
    { .extn_id = "2.5.29.9", .extn_name = "subject_directory_attributes",
#ifdef HAVE_LIBJANSSON
        NULL
#endif
    },
    { .extn_id = "2.5.29.31", .extn_name = "crl_distribution_points",
#ifdef HAVE_LIBJANSSON
        NULL
#endif
    },
    { .extn_id = "2.5.29.16", .extn_name = "private_key_usage_period",
#ifdef HAVE_LIBJANSSON
        NULL
#endif
    },
    { .extn_id = "2.5.29.32", .extn_name = "certificate_policies",
#ifdef HAVE_LIBJANSSON
        NULL
#endif
    },
    { .extn_id = "2.5.29.33", .extn_name = "policy_mappings",
#ifdef HAVE_LIBJANSSON
        NULL
#endif
    },
    { .extn_id = "2.5.29.54", .extn_name = "inhibit_any_policy",
#ifdef HAVE_LIBJANSSON
        NULL
#endif
    },
};

static int GetAsnExtension(SSLCertExtension *extn)
{
    int i;

    if (extn->extn_id == NULL) {
        return -1;
    }

    for (i = 0; i < EXTN_MAX; i++) {
        if (!strcmp(extn->extn_id, asn_extns[i].extn_id))
            return i;
    }

    return -1;
}

static const char *Oid2ExtensionName(const char *oid)
{
    int i;

    for (i = 0; i < EXTN_MAX; i++) {
        if (strcmp(oid, asn_extns[i].extn_id) == 0) {
            return asn_extns[i].extn_name;
        }
    }

    return "unknown";
}

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

static const char *Oid2SignatureAlgoStr(const char *oid)
{
    if (strcmp(oid, "1.2.840.113549.1.1.11") == 0)
        return "PKCS #1 SHA-256 With RSA Encryption";

    if (strcmp(oid, "1.2.840.113549.1.1.12") == 0)
        return "PKCS #1 SHA-348 With RSA Encryption";

    if (strcmp(oid, "1.2.840.113549.1.1.13") == 0)
        return "PKCS #1 SHA-512 With RSA Encryption";

    if (strcmp(oid, "1.2.840.10040.4.3") == 0)
        return "PKCS #1 DSA With SHA-1";

    if (strcmp(oid, "2.16.840.1.101.3.4.3.2") == 0)
        return "PKCS #1 DSA With SHA-256";

    if (strcmp(oid, "1.2.840.10045.4.1") == 0)
        return "PKCS #1 ECDSA With SHA-1";

    if (strcmp(oid, "1.2.840.10045.4.3.2") == 0)
        return "PKCS #1 ECDSA With SHA-256";

    if (strcmp(oid, "1.2.840.10045.4.3.3") == 0)
        return "PKCS #1 ECDSA With SHA-384";

    if (strcmp(oid, "1.2.840.10045.4.3.4") == 0)
        return "PKCS #1 ECDSA With SHA-512";

    if (strcmp(oid, "1.2.840.113549.1.1.10") == 0)
        return "PKCS #1 RSASSA-PSS With default parameters";

    if (strcmp(oid, "1.2.840.113549.1.1.10") == 0)
        return "PKCS #1 RSASSA-PSS With SHA-256";

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

int Asn1DerGetSubjectPublicKeyAlgo(const Asn1Generic *cert, char *buffer,
                                   uint32_t length, uint32_t *errcode)
{
    const Asn1Generic *node;
    int rc = -1;

    if (errcode)
        *errcode = ERR_DER_MISSING_ELEMENT;

    buffer[0] = '\0';

    node = Asn1DerGet(cert, SEQ_IDX_SUBJECT_PK, sizeof(SEQ_IDX_SUBJECT_PK), errcode);
    if ((node == NULL) || node->type != ASN1_SEQUENCE)
        goto subject_pk_error;

    node = node->data;
    if ((node == NULL) || node->type != ASN1_SEQUENCE)
        goto subject_pk_error;

    /* we're looking for the OID, but actually 'node'
     * points to a SEQUENCE, so we need to access
     * and get the first element which is the OID. */
    node = node->data;
    if ((node == NULL) || node->type != ASN1_OID)
        goto subject_pk_error;

    if (node->length > length) {
        if (errcode)
            *errcode = ERR_DER_ELEMENT_SIZE_TOO_BIG;
        goto subject_pk_error;
    }

    strlcat(buffer, node->str, length);

    if (errcode)
        *errcode = 0;

    rc = 0;

subject_pk_error:
    return rc;
}

int Asn1DerGetCertSignatureAlgo(const Asn1Generic *cert, char *buffer,
                                uint32_t length, uint32_t *errcode)
{
    const Asn1Generic *node;
    const char *signature_algorithm;
    int rc = -1;

    if (errcode)
        *errcode = ERR_DER_MISSING_ELEMENT;

    buffer[0] = '\0';

    node = Asn1DerGet(cert, SEQ_IDX_CERT_SIGNATURE_ALGO,
                     sizeof(SEQ_IDX_CERT_SIGNATURE_ALGO), errcode);
    if ((node == NULL) || node->type != ASN1_SEQUENCE)
        goto cert_signature_error;

    node = node->data;
    if ((node == NULL) || node->type != ASN1_OID)
        goto cert_signature_error;

    signature_algorithm = Oid2SignatureAlgoStr(node->str);
    if (strlen(signature_algorithm) > length) {
        if (errcode)
            *errcode = ERR_DER_ELEMENT_SIZE_TOO_BIG;

        goto cert_signature_error;
    }
    strlcat(buffer, signature_algorithm, length);

    if (errcode)
        *errcode = 0;

    rc = 0;

cert_signature_error:
    return rc;
}

int Asn1DerGetSignatureAlgo(const Asn1Generic *cert, char *buffer,
                            uint32_t length, uint32_t *errcode)
{
    const Asn1Generic *node;
    const char *signature_algorithm;
    int rc = -1;

    if (errcode)
        *errcode = ERR_DER_MISSING_ELEMENT;

    buffer[0] = '\0';

    node = Asn1DerGet(cert, SEQ_IDX_SIGNATURE_ALGO, sizeof(SEQ_IDX_SIGNATURE_ALGO), errcode);
    if ((node == NULL) || node->type != ASN1_OID)
        goto signature_error;

    signature_algorithm = Oid2SignatureAlgoStr(node->str);
    if (strlen(signature_algorithm) > length) {
        if (errcode)
            *errcode = ERR_DER_ELEMENT_SIZE_TOO_BIG;

         goto signature_error;
    }
    strlcat(buffer, signature_algorithm, length);

    if (errcode)
        *errcode = 0;

    rc = 0;

signature_error:
    return rc;
}

int Asn1DerGetExtensions(const Asn1Generic *cert, SSLStateConnp *server_connp,
                         uint32_t *errcode)
{
    const Asn1Generic *node = cert->data->next;
    const Asn1Generic *it;
    const Asn1Generic *extns_node;
    const Asn1Generic *extn;
    const Asn1Generic *extn_node;
    int rc = -1;

    if (node == NULL || node->data == NULL)
        return rc;

    /* get the sequence of extensions */
    while (node->data->header.cls != ASN1_CLASS_CONTEXTSPEC) {
        node = node->next;
        if (node == NULL || node->data == NULL) {
            SCLogInfo("node == NULL || node->data == NULL");
            return rc;
        }
    }

    /* extensions field */
    extns_node = node->data;
    if (extns_node == NULL || extns_node->header.cls != ASN1_CLASS_CONTEXTSPEC)
        return rc;

    if (extns_node->type != ASN1_SEQUENCE)
        return rc;

    /* list of extension */
    it = extns_node->data;
    if (it == NULL)
        return rc;

    if (it->type != ASN1_SEQUENCE)
        return rc;

    while (it != NULL) {
        extn = it->data;
        SSLCertExtension *nextn;
        nextn = (SSLCertExtension *)SCMalloc(sizeof(SSLCertExtension));
        if (nextn == NULL)
            return rc;
        memset(nextn, 0, sizeof(*nextn));

        /* iterate extension's field */
        while (extn != NULL) {
            extn_node = extn->data;

            if (extn_node == NULL) {
                goto next;
            }

            switch (extn_node->type) {
                case ASN1_OID:
                    nextn->extn_id = SCStrdup(extn_node->str);
                    if (nextn->extn_id == NULL) {
                        SCFree(nextn);
                        SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate extension");
                        return rc;
                    }
                    nextn->extn_name = Oid2ExtensionName(extn_node->str);
                    break;
                case ASN1_INTEGER:
                    nextn->critical = extn_node->value;
                    break;
                case ASN1_OCTETSTRING:
                    nextn->extn_value = SCMalloc(extn_node->strlen);
                    nextn->extn_length = (size_t)extn_node->strlen;
                    if (nextn->extn_value == NULL) {
                        SCFree(nextn);
                        SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate extension");
                        return rc;
                    }
                    memcpy(nextn->extn_value, extn_node->str, extn_node->strlen);
                    break;
                default: /* Unsupported type */
                    break;
            }
        next:
            extn = extn->next;
        }
        if (strcmp(nextn->extn_name, "unknown") != 0 && nextn->extn_id && nextn->extn_value) {
            TAILQ_INSERT_TAIL(&server_connp->extns, nextn, next);
        } else {
            if (nextn->extn_id)
                SCFree(nextn->extn_id);
            if (nextn->extn_value)
                SCFree(nextn->extn_value);
            SCFree(nextn);
        }

        it = it->next;
    }

    return 0;
}

#ifdef HAVE_LIBJANSSON
json_t *Asn1DerGetExtensionValueAsJSON(SSLCertExtension *extn)
{
    int id = GetAsnExtension(extn);
    if (id != -1 && asn_extns[id].ExtnGetValueAsJson) {
        return asn_extns[id].ExtnGetValueAsJson(extn);
    }

    return json_string("unknown");
}
#endif

