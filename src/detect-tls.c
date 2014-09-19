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
 * Implements the tls.* keywords
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "app-layer.h"

#include "app-layer-ssl.h"
#include "detect-tls.h"

#include "stream-tcp.h"

/**
 * \brief Regex for parsing "id" option, matching number or "number"
 */

#define PARSE_REGEX  "^\\s*(\\!*)\\s*([A-z0-9\\s\\-\\.=,\\*@]+|\"[A-z0-9\\s\\-\\.=,\\*@]+\")\\s*$"
#define PARSE_REGEX_FINGERPRINT  "^\\s*(\\!*)\\s*([A-z0-9\\:\\*]+|\"[A-z0-9\\:\\* ]+\")\\s*$"

static pcre *subject_parse_regex;
static pcre_extra *subject_parse_regex_study;
static pcre *issuerdn_parse_regex;
static pcre_extra *issuerdn_parse_regex_study;
static pcre *fingerprint_parse_regex;
static pcre_extra *fingerprint_parse_regex_study;

static int DetectTlsSubjectMatch (ThreadVars *, DetectEngineThreadCtx *, Flow *, uint8_t, void *, Signature *, SigMatch *);
static int DetectTlsSubjectSetup (DetectEngineCtx *, Signature *, char *);
static void DetectTlsSubjectRegisterTests(void);
static void DetectTlsSubjectFree(void *);
static int DetectTlsIssuerDNMatch (ThreadVars *, DetectEngineThreadCtx *, Flow *, uint8_t, void *, Signature *, SigMatch *);
static int DetectTlsIssuerDNSetup (DetectEngineCtx *, Signature *, char *);
static void DetectTlsIssuerDNRegisterTests(void);
static void DetectTlsIssuerDNFree(void *);
static int DetectTlsFingerprintMatch (ThreadVars *, DetectEngineThreadCtx *, Flow *, uint8_t, void *, Signature *, SigMatch *);
static int DetectTlsFingerprintSetup (DetectEngineCtx *, Signature *, char *);
static void DetectTlsFingerprintFree(void *);
static int DetectTlsStoreSetup (DetectEngineCtx *, Signature *, char *);
static int DetectTlsStoreMatch (ThreadVars *, DetectEngineThreadCtx *, Flow *, uint8_t, void *, Signature *, SigMatch *);

/**
 * \brief Registration function for keyword: tls.version
 */
void DetectTlsRegister (void)
{
    sigmatch_table[DETECT_AL_TLS_SUBJECT].name = "tls.subject";
    sigmatch_table[DETECT_AL_TLS_SUBJECT].desc = "match TLS/SSL certificate Subject field";
    sigmatch_table[DETECT_AL_TLS_SUBJECT].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/TLS-keywords#tlssubject";
    sigmatch_table[DETECT_AL_TLS_SUBJECT].Match = NULL;
    sigmatch_table[DETECT_AL_TLS_SUBJECT].AppLayerMatch = DetectTlsSubjectMatch;
    sigmatch_table[DETECT_AL_TLS_SUBJECT].alproto = ALPROTO_TLS;
    sigmatch_table[DETECT_AL_TLS_SUBJECT].Setup = DetectTlsSubjectSetup;
    sigmatch_table[DETECT_AL_TLS_SUBJECT].Free  = DetectTlsSubjectFree;
    sigmatch_table[DETECT_AL_TLS_SUBJECT].RegisterTests = DetectTlsSubjectRegisterTests;

    sigmatch_table[DETECT_AL_TLS_ISSUERDN].name = "tls.issuerdn";
    sigmatch_table[DETECT_AL_TLS_ISSUERDN].desc = "match TLS/SSL certificate IssuerDN field";
    sigmatch_table[DETECT_AL_TLS_ISSUERDN].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/TLS-keywords#tlsissuerdn";
    sigmatch_table[DETECT_AL_TLS_ISSUERDN].Match = NULL;
    sigmatch_table[DETECT_AL_TLS_ISSUERDN].AppLayerMatch = DetectTlsIssuerDNMatch;
    sigmatch_table[DETECT_AL_TLS_ISSUERDN].alproto = ALPROTO_TLS;
    sigmatch_table[DETECT_AL_TLS_ISSUERDN].Setup = DetectTlsIssuerDNSetup;
    sigmatch_table[DETECT_AL_TLS_ISSUERDN].Free  = DetectTlsIssuerDNFree;
    sigmatch_table[DETECT_AL_TLS_ISSUERDN].RegisterTests = DetectTlsIssuerDNRegisterTests;

    sigmatch_table[DETECT_AL_TLS_FINGERPRINT].name = "tls.fingerprint";
    sigmatch_table[DETECT_AL_TLS_FINGERPRINT].desc = "match TLS/SSL certificate SHA1 fingerprint";
    sigmatch_table[DETECT_AL_TLS_FINGERPRINT].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/TLS-keywords#tlsfingerprint";
    sigmatch_table[DETECT_AL_TLS_FINGERPRINT].Match = NULL;
    sigmatch_table[DETECT_AL_TLS_FINGERPRINT].AppLayerMatch = DetectTlsFingerprintMatch;
    sigmatch_table[DETECT_AL_TLS_FINGERPRINT].alproto = ALPROTO_TLS;
    sigmatch_table[DETECT_AL_TLS_FINGERPRINT].Setup = DetectTlsFingerprintSetup;
    sigmatch_table[DETECT_AL_TLS_FINGERPRINT].Free  = DetectTlsFingerprintFree;
    sigmatch_table[DETECT_AL_TLS_FINGERPRINT].RegisterTests = NULL;

    sigmatch_table[DETECT_AL_TLS_STORE].name = "tls.store";
    sigmatch_table[DETECT_AL_TLS_STORE].desc = "store TLS/SSL certificate on disk";
    sigmatch_table[DETECT_AL_TLS_STORE].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/TLS-keywords#tlsstore";
    sigmatch_table[DETECT_AL_TLS_STORE].Match = NULL;
    sigmatch_table[DETECT_AL_TLS_STORE].AppLayerMatch = DetectTlsStoreMatch;
    sigmatch_table[DETECT_AL_TLS_STORE].alproto = ALPROTO_TLS;
    sigmatch_table[DETECT_AL_TLS_STORE].Setup = DetectTlsStoreSetup;
    sigmatch_table[DETECT_AL_TLS_STORE].Free  = NULL;
    sigmatch_table[DETECT_AL_TLS_STORE].RegisterTests = NULL;
    sigmatch_table[DETECT_AL_TLS_STORE].flags |= SIGMATCH_NOOPT;

    const char *eb;
    int eo;
    int opts = 0;

    SCLogDebug("registering tls.subject rule option");

    subject_parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if (subject_parse_regex == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "Compile of \"%s\" failed at offset %" PRId32 ": %s",
                    PARSE_REGEX, eo, eb);
        goto error;
    }

    subject_parse_regex_study = pcre_study(subject_parse_regex, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }

    SCLogDebug("registering tls.issuerdn rule option");

    issuerdn_parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if (issuerdn_parse_regex == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "Compile of \"%s\" failed at offset %" PRId32 ": %s",
                PARSE_REGEX, eo, eb);
        goto error;
    }

    issuerdn_parse_regex_study = pcre_study(issuerdn_parse_regex, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }

    SCLogDebug("registering tls.fingerprint rule option");

    fingerprint_parse_regex = pcre_compile(PARSE_REGEX_FINGERPRINT, opts, &eb, &eo, NULL);
    if (fingerprint_parse_regex == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "Compile of \"%s\" failed at offset %" PRId32 ": %s", PARSE_REGEX_FINGERPRINT, eo, eb);
        goto error;
    }

    fingerprint_parse_regex_study = pcre_study(fingerprint_parse_regex, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }

    return;

error:
    return;
}

/**
 * \brief match the specified Subject on a tls session
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectTlsData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectTlsSubjectMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags, void *state, Signature *s, SigMatch *m)
{
    SCEnter();

    DetectTlsData *tls_data = (DetectTlsData *)m->ctx;
    SSLState *ssl_state = (SSLState *)state;
    if (ssl_state == NULL) {
        SCLogDebug("no tls state, no match");
        SCReturnInt(0);
    }

    int ret = 0;

    SSLStateConnp *connp = NULL;
    if (flags & STREAM_TOSERVER) {
        connp = &ssl_state->client_connp;
    } else {
        connp = &ssl_state->server_connp;
    }

    if (connp->cert0_subject != NULL) {
        SCLogDebug("TLS: Subject is [%s], looking for [%s]\n",
                   connp->cert0_subject, tls_data->subject);

        if (strstr(connp->cert0_subject, tls_data->subject) != NULL) {
            if (tls_data->flags & DETECT_CONTENT_NEGATED) {
                ret = 0;
            } else {
                ret = 1;
            }
        } else {
            if (tls_data->flags & DETECT_CONTENT_NEGATED) {
                ret = 1;
            } else {
                ret = 0;
            }
        }
    } else {
        ret = 0;
    }

    SCReturnInt(ret);
}

/**
 * \brief This function is used to parse IPV4 ip_id passed via keyword: "id"
 *
 * \param idstr Pointer to the user provided id option
 *
 * \retval id_d pointer to DetectTlsData on success
 * \retval NULL on failure
 */
static DetectTlsData *DetectTlsSubjectParse (char *str)
{
    DetectTlsData *tls = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    const char *str_ptr;
    char *orig = NULL;
    char *tmp_str;
    uint32_t flag = 0;

    ret = pcre_exec(subject_parse_regex, subject_parse_regex_study, str, strlen(str), 0, 0,
                    ov, MAX_SUBSTRINGS);

    if (ret != 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "invalid tls.subject option");
        goto error;
    }

    res = pcre_get_substring((char *)str, ov, MAX_SUBSTRINGS, 1, &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }
    if (str_ptr[0] == '!')
        flag = DETECT_CONTENT_NEGATED;

    res = pcre_get_substring((char *)str, ov, MAX_SUBSTRINGS, 2, &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }

    /* We have a correct id option */
    tls = SCMalloc(sizeof(DetectTlsData));
    if (unlikely(tls == NULL))
        goto error;
    tls->subject = NULL;
    tls->flags = flag;

    orig = SCStrdup((char*)str_ptr);
    if (unlikely(orig == NULL)) {
        goto error;
    }
    tmp_str=orig;

    /* Let's see if we need to escape "'s */
    if (tmp_str[0] == '"') {
        tmp_str[strlen(tmp_str) - 1] = '\0';
        tmp_str += 1;
    }

    tls->subject = SCStrdup(tmp_str);
    if (unlikely(tls->subject == NULL)) {
        goto error;
    }

    SCFree(orig);

    SCLogDebug("will look for TLS subject %s", tls->subject);

    return tls;

error:
    if (orig != NULL)
        SCFree(orig);
    if (tls != NULL)
        DetectTlsSubjectFree(tls);
    return NULL;

}

/**
 * \brief this function is used to add the parsed "id" option
 * \brief into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param idstr pointer to the user provided "id" option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectTlsSubjectSetup (DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    DetectTlsData *tls = NULL;
    SigMatch *sm = NULL;

    tls = DetectTlsSubjectParse(str);
    if (tls == NULL)
        goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_TLS) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords.");
        goto error;
    }

    sm->type = DETECT_AL_TLS_SUBJECT;
    sm->ctx = (void *)tls;

    s->flags |= SIG_FLAG_APPLAYER;
    s->alproto = ALPROTO_TLS;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_AMATCH);

    return 0;

error:
    if (tls != NULL)
        DetectTlsSubjectFree(tls);
    if (sm != NULL)
        SCFree(sm);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectTlsData
 *
 * \param id_d pointer to DetectTlsData
 */
static void DetectTlsSubjectFree(void *ptr)
{
    DetectTlsData *id_d = (DetectTlsData *)ptr;
    if (ptr == NULL)
        return;
    if (id_d->subject != NULL)
        SCFree(id_d->subject);
    SCFree(id_d);
}

/**
 * \brief this function registers unit tests for DetectTlsSubject
 */
static void DetectTlsSubjectRegisterTests(void)
{
}

/**
 * \brief match the specified IssuerDN on a tls session
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectTlsData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectTlsIssuerDNMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags, void *state, Signature *s, SigMatch *m)
{
    SCEnter();

    DetectTlsData *tls_data = (DetectTlsData *)m->ctx;
    SSLState *ssl_state = (SSLState *)state;
    if (ssl_state == NULL) {
        SCLogDebug("no tls state, no match");
        SCReturnInt(0);
    }

    int ret = 0;

    SSLStateConnp *connp = NULL;
    if (flags & STREAM_TOSERVER) {
        connp = &ssl_state->client_connp;
    } else {
        connp = &ssl_state->server_connp;
    }

    if (connp->cert0_issuerdn != NULL) {
        SCLogDebug("TLS: IssuerDN is [%s], looking for [%s]\n",
                   connp->cert0_issuerdn, tls_data->issuerdn);

        if (strstr(connp->cert0_issuerdn, tls_data->issuerdn) != NULL) {
            if (tls_data->flags & DETECT_CONTENT_NEGATED) {
                ret = 0;
            } else {
                ret = 1;
            }
        } else {
            if (tls_data->flags & DETECT_CONTENT_NEGATED) {
                ret = 1;
            } else {
                ret = 0;
            }
        }
    } else {
        ret = 0;
    }

    SCReturnInt(ret);
}

/**
 * \brief This function is used to parse IPV4 ip_id passed via keyword: "id"
 *
 * \param idstr Pointer to the user provided id option
 *
 * \retval id_d pointer to DetectTlsData on success
 * \retval NULL on failure
 */
static DetectTlsData *DetectTlsIssuerDNParse(char *str)
{
    DetectTlsData *tls = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    const char *str_ptr;
    char *orig = NULL;
    char *tmp_str;
    uint32_t flag = 0;

    ret = pcre_exec(issuerdn_parse_regex, issuerdn_parse_regex_study, str, strlen(str), 0, 0,
                    ov, MAX_SUBSTRINGS);

    if (ret != 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "invalid tls.issuerdn option");
        goto error;
    }

    res = pcre_get_substring((char *)str, ov, MAX_SUBSTRINGS, 1, &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }
    if (str_ptr[0] == '!')
        flag = DETECT_CONTENT_NEGATED;

    res = pcre_get_substring((char *)str, ov, MAX_SUBSTRINGS, 2, &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }

    /* We have a correct id option */
    tls = SCMalloc(sizeof(DetectTlsData));
    if (unlikely(tls == NULL))
        goto error;
    tls->issuerdn = NULL;
    tls->flags = flag;

    orig = SCStrdup((char*)str_ptr);
    if (unlikely(orig == NULL)) {
        goto error;
    }
    tmp_str=orig;

    /* Let's see if we need to escape "'s */
    if (tmp_str[0] == '"')
    {
        tmp_str[strlen(tmp_str) - 1] = '\0';
        tmp_str += 1;
    }

    tls->issuerdn = SCStrdup(tmp_str);
    if (unlikely(tls->issuerdn == NULL)) {
        goto error;
    }

    SCFree(orig);

    SCLogDebug("Will look for TLS issuerdn %s", tls->issuerdn);

    return tls;

error:
    if (orig != NULL)
        SCFree(orig);
    if (tls != NULL)
        DetectTlsIssuerDNFree(tls);
    return NULL;

}

/**
 * \brief this function is used to add the parsed "id" option
 * \brief into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param idstr pointer to the user provided "id" option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectTlsIssuerDNSetup (DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    DetectTlsData *tls = NULL;
    SigMatch *sm = NULL;

    tls = DetectTlsIssuerDNParse(str);
    if (tls == NULL)
        goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_TLS) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords.");
        goto error;
    }

    sm->type = DETECT_AL_TLS_ISSUERDN;
    sm->ctx = (void *)tls;

    s->flags |= SIG_FLAG_APPLAYER;
    s->alproto = ALPROTO_TLS;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_AMATCH);

    return 0;

error:
    if (tls != NULL)
        DetectTlsIssuerDNFree(tls);
    if (sm != NULL)
        SCFree(sm);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectTlsData
 *
 * \param id_d pointer to DetectTlsData
 */
static void DetectTlsIssuerDNFree(void *ptr)
{
    DetectTlsData *id_d = (DetectTlsData *)ptr;
    SCFree(id_d->issuerdn);
    SCFree(id_d);
}

/**
 * \brief This function is used to parse fingerprint passed via keyword: "fingerprint"
 *
 * \param idstr Pointer to the user provided fingerprint option
 *
 * \retval pointer to DetectTlsData on success
 * \retval NULL on failure
 */
static DetectTlsData *DetectTlsFingerprintParse (char *str)
{
    DetectTlsData *tls = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    const char *str_ptr;
    char *orig;
    char *tmp_str;
    uint32_t flag = 0;

    ret = pcre_exec(fingerprint_parse_regex, fingerprint_parse_regex_study, str, strlen(str), 0, 0,
                    ov, MAX_SUBSTRINGS);

    if (ret != 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "invalid tls.fingerprint option");
        goto error;
    }

    res = pcre_get_substring((char *)str, ov, MAX_SUBSTRINGS, 1, &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }
    if (str_ptr[0] == '!')
        flag = DETECT_CONTENT_NEGATED;

    res = pcre_get_substring((char *)str, ov, MAX_SUBSTRINGS, 2, &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }

    /* We have a correct id option */
    tls = SCMalloc(sizeof(DetectTlsData));
    if (unlikely(tls == NULL))
        goto error;
    tls->fingerprint = NULL;
    tls->flags = flag;

    orig = SCStrdup((char*)str_ptr);
    if (unlikely(orig == NULL)) {
        goto error;
    }
    tmp_str=orig;

    /* Let's see if we need to escape "'s */
    if (tmp_str[0] == '"')
    {
        tmp_str[strlen(tmp_str) - 1] = '\0';
        tmp_str += 1;
    }

    tls->fingerprint = SCStrdup(tmp_str);
    if (tls->fingerprint == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate fingerprint");
    }

    SCFree(orig);

    SCLogDebug("will look for TLS fingerprint %s", tls->fingerprint);

    return tls;

error:
    if (tls != NULL)
        DetectTlsFingerprintFree(tls);
    return NULL;

}
/**
 * \brief match the specified fingerprint on a tls session
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectTlsData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectTlsFingerprintMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags, void *state, Signature *s, SigMatch *m)
{
    SCEnter();
    DetectTlsData *tls_data = (DetectTlsData *)m->ctx;
    SSLState *ssl_state = (SSLState *)state;
    if (ssl_state == NULL) {
        SCLogDebug("no tls state, no match");
        SCReturnInt(0);
    }

    int ret = 0;

    if (ssl_state->server_connp.cert0_fingerprint != NULL) {
        SCLogDebug("TLS: Fingerprint is [%s], looking for [%s]\n",
                   ssl_state->server_connp.cert0_fingerprint,
                   tls_data->fingerprint);

        if (tls_data->fingerprint &&
            (strstr(ssl_state->server_connp.cert0_fingerprint,
                    tls_data->fingerprint) != NULL)) {
            if (tls_data->flags & DETECT_CONTENT_NEGATED) {
                ret = 0;
            } else {
                ret = 1;

            }
        } else {
            if (tls_data->flags & DETECT_CONTENT_NEGATED) {
                ret = 1;
            } else {
                ret = 0;
            }
        }
    } else {
        ret = 0;
    }

    SCReturnInt(ret);
}

/**
 * \brief this function is used to add the parsed "fingerprint" option
 * \brief into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param id pointer to the user provided "fingerprint" option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectTlsFingerprintSetup (DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    DetectTlsData *tls = NULL;
    SigMatch *sm = NULL;

    tls = DetectTlsFingerprintParse(str);
    if (tls == NULL)
        goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_TLS) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords.");
        goto error;
    }

    sm->type = DETECT_AL_TLS_FINGERPRINT;
    sm->ctx = (void *)tls;

    s->flags |= SIG_FLAG_APPLAYER;
    s->alproto = ALPROTO_TLS;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_AMATCH);

    return 0;

error:
    if (tls != NULL)
        DetectTlsFingerprintFree(tls);
    if (sm != NULL)
        SCFree(sm);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectTlsData
 *
 * \param pointer to DetectTlsData
 */
static void DetectTlsFingerprintFree(void *ptr)
{
    DetectTlsData *id_d = (DetectTlsData *)ptr;
    if (id_d->fingerprint)
        SCFree(id_d->fingerprint);
    SCFree(id_d);
}

/**
 * \brief this function is used to add the parsed "store" option
 * \brief into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param idstr pointer to the user provided "store" option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectTlsStoreSetup (DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    SigMatch *sm = NULL;

    s->flags |= SIG_FLAG_TLSSTORE;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_TLS) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords.");
        goto error;
    }

    sm->type = DETECT_AL_TLS_STORE;
    s->flags |= SIG_FLAG_APPLAYER;
    s->alproto = ALPROTO_TLS;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_AMATCH);

    return 0;

error:
    if (sm != NULL)
        SCFree(sm);
    return -1;

}

/** \warning modifies state */
static int DetectTlsStoreMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags, void *state, Signature *s, SigMatch *m)
{
    SCEnter();

    SSLState *ssl_state = (SSLState *)state;
    if (ssl_state == NULL) {
        SCLogDebug("no tls state, no match");
        SCReturnInt(1);
    }

    if (s->flags & SIG_FLAG_TLSSTORE) {
        ssl_state->server_connp.cert_log_flag |= SSL_TLS_LOG_PEM;
    }

    SCReturnInt(1);
}


/**
 * \brief this function registers unit tests for DetectTlsIssuerDN
 */
static void DetectTlsIssuerDNRegisterTests(void)
{
}
