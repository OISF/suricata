/* Copyright (C) 2007-2014 Open Information Security Foundation
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
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 *
 * Implements the ssh.protoversion keyword
 * You can specify a concrete version like ssh.protoversion: 1.66
 * or search for protoversion 2 compat (1.99 is considered as 2) like
 * ssh.protoversion:2_compat
 * or just the beginning of the string like ssh.protoversion:"1."
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
#include "app-layer-parser.h"
#include "app-layer-ssh.h"
#include "detect-ssh-proto-version.h"

#include "stream-tcp.h"

/**
 * \brief Regex for parsing the protoversion string
 */
#define PARSE_REGEX  "^\\s*\"?\\s*([0-9]+([\\.\\-0-9]+)?|2_compat)\\s*\"?\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

int DetectSshVersionMatch (ThreadVars *, DetectEngineThreadCtx *, Flow *, uint8_t, void *, Signature *, SigMatch *);
static int DetectSshVersionSetup (DetectEngineCtx *, Signature *, char *);
void DetectSshVersionRegisterTests(void);
void DetectSshVersionFree(void *);

/**
 * \brief Registration function for keyword: ssh.protoversion
 */
void DetectSshVersionRegister(void)
{
    sigmatch_table[DETECT_AL_SSH_PROTOVERSION].name = "ssh.protoversion";
    sigmatch_table[DETECT_AL_SSH_PROTOVERSION].Match = NULL;
    sigmatch_table[DETECT_AL_SSH_PROTOVERSION].AppLayerMatch = DetectSshVersionMatch;
    sigmatch_table[DETECT_AL_SSH_PROTOVERSION].alproto = ALPROTO_SSH;
    sigmatch_table[DETECT_AL_SSH_PROTOVERSION].Setup = DetectSshVersionSetup;
    sigmatch_table[DETECT_AL_SSH_PROTOVERSION].Free  = DetectSshVersionFree;
    sigmatch_table[DETECT_AL_SSH_PROTOVERSION].RegisterTests = DetectSshVersionRegisterTests;

    const char *eb;
    int eo;
    int opts = 0;

	SCLogDebug("registering ssh.protoversion rule option");

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if (parse_regex == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "Compile of \"%s\" failed at offset %" PRId32 ": %s",
                    PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }
    return;

error:
    return;
}

/**
 * \brief match the specified version on a ssh session
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectSshVersionData
 *
 * \retval 0 no match
 * \retval 1 match
 */
int DetectSshVersionMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags, void *state, Signature *s, SigMatch *m)
{
    SCEnter();

    DetectSshVersionData *ssh = (DetectSshVersionData *)m->ctx;
    SshState *ssh_state = (SshState *)state;
    if (ssh_state == NULL) {
        SCLogDebug("no ssh state, no match");
        SCReturnInt(0);
    }

    int ret = 0;
    if ((flags & STREAM_TOCLIENT) && (ssh_state->srv_hdr.flags & SSH_FLAG_VERSION_PARSED)) {
        if (ssh->flags & SSH_FLAG_PROTOVERSION_2_COMPAT) {
            SCLogDebug("looking for ssh server protoversion 2 compat");
            if (strncmp((char *) ssh_state->srv_hdr.proto_version, "2", 1) == 0 ||
                strncmp((char *) ssh_state->srv_hdr.proto_version, "2.", 2) == 0 ||
                strncmp((char *) ssh_state->srv_hdr.proto_version, "1.99", 4) == 0)
                ret = 1;
        } else {
            SCLogDebug("looking for ssh server protoversion %s length %"PRIu16"", ssh->ver, ssh->len);
            ret = (strncmp((char *) ssh_state->srv_hdr.proto_version, (char *) ssh->ver, ssh->len) == 0)? 1 : 0;
        }
    } else if ((flags & STREAM_TOSERVER) && (ssh_state->cli_hdr.flags & SSH_FLAG_VERSION_PARSED)) {
        if (ssh->flags & SSH_FLAG_PROTOVERSION_2_COMPAT) {
            SCLogDebug("looking for client ssh client protoversion 2 compat");
            if (strncmp((char *) ssh_state->cli_hdr.proto_version, "2", 1) == 0 ||
                strncmp((char *) ssh_state->cli_hdr.proto_version, "2.", 2) == 0 ||
                strncmp((char *) ssh_state->cli_hdr.proto_version, "1.99", 4) == 0)
                ret = 1;
        } else {
            SCLogDebug("looking for ssh client protoversion %s length %"PRIu16"", ssh->ver, ssh->len);
            ret = (strncmp((char *) ssh_state->cli_hdr.proto_version, (char *) ssh->ver, ssh->len) == 0)? 1 : 0;
        }
    }
    SCReturnInt(ret);
}

/**
 * \brief This function is used to parse IPV4 ip_id passed via keyword: "id"
 *
 * \param idstr Pointer to the user provided id option
 *
 * \retval id_d pointer to DetectSshVersionData on success
 * \retval NULL on failure
 */
DetectSshVersionData *DetectSshVersionParse (char *str)
{
    DetectSshVersionData *ssh = NULL;
	#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, str, strlen(str), 0, 0,
                    ov, MAX_SUBSTRINGS);

    if (ret < 1 || ret > 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "invalid ssh.protoversion option");
        goto error;
    }

    if (ret > 1) {
        const char *str_ptr;
        res = pcre_get_substring((char *)str, ov, MAX_SUBSTRINGS, 1, &str_ptr);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }

        /* We have a correct id option */
        ssh = SCMalloc(sizeof(DetectSshVersionData));
        if (unlikely(ssh == NULL))
            goto error;

        memset(ssh, 0x00, sizeof(DetectSshVersionData));

        /* If we expect a protocol version 2 or 1.99 (considered 2, we
         * will compare it with both strings) */
        if (strcmp("2_compat", str_ptr) == 0) {
            ssh->flags |= SSH_FLAG_PROTOVERSION_2_COMPAT;
            SCLogDebug("will look for ssh protocol version 2 (2, 2.0, 1.99 that's considered as 2");
            return ssh;
        }

        ssh->ver = (uint8_t *)SCStrdup((char*)str_ptr);
        if (ssh->ver == NULL) {
            goto error;
        }
        ssh->len = strlen((char *) ssh->ver);

        SCLogDebug("will look for ssh %s", ssh->ver);
    }

    return ssh;

error:
    if (ssh != NULL)
        DetectSshVersionFree(ssh);
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
static int DetectSshVersionSetup (DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    DetectSshVersionData *ssh = NULL;
    SigMatch *sm = NULL;

    ssh = DetectSshVersionParse(str);
    if (ssh == NULL)
        goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_SSH) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords.");
        goto error;
    }

    sm->type = DETECT_AL_SSH_PROTOVERSION;
    sm->ctx = (void *)ssh;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_AMATCH);

    s->flags |= SIG_FLAG_APPLAYER;
    s->alproto = ALPROTO_SSH;
    return 0;

error:
    if (ssh != NULL)
        DetectSshVersionFree(ssh);
    if (sm != NULL)
        SCFree(sm);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectSshVersionData
 *
 * \param id_d pointer to DetectSshVersionData
 */
void DetectSshVersionFree(void *ptr)
{
    DetectSshVersionData *id_d = (DetectSshVersionData *)ptr;
    SCFree(id_d);
}

#ifdef UNITTESTS /* UNITTESTS */

/**
 * \test DetectSshVersionTestParse01 is a test to make sure that we parse
 *       a proto version correctly
 */
int DetectSshVersionTestParse01 (void)
{
    DetectSshVersionData *ssh = NULL;
    ssh = DetectSshVersionParse("1.0");
    if (ssh != NULL && strncmp((char *) ssh->ver, "1.0", 3) == 0) {
        DetectSshVersionFree(ssh);
        return 1;
    }

    return 0;
}

/**
 * \test DetectSshVersionTestParse02 is a test to make sure that we parse
 *       the proto version (compatible with proto version 2) correctly
 */
int DetectSshVersionTestParse02 (void)
{
    DetectSshVersionData *ssh = NULL;
    ssh = DetectSshVersionParse("2_compat");
    if (ssh->flags & SSH_FLAG_PROTOVERSION_2_COMPAT) {
        DetectSshVersionFree(ssh);
        return 1;
    }

    return 0;
}

/**
 * \test DetectSshVersionTestParse03 is a test to make sure that we
 *       don't return a ssh_data with an invalid value specified
 */
int DetectSshVersionTestParse03 (void)
{
    DetectSshVersionData *ssh = NULL;
    ssh = DetectSshVersionParse("2_com");
    if (ssh != NULL) {
        DetectSshVersionFree(ssh);
        return 0;
    }
    ssh = DetectSshVersionParse("");
    if (ssh != NULL) {
        DetectSshVersionFree(ssh);
        return 0;
    }
    ssh = DetectSshVersionParse(".1");
    if (ssh != NULL) {
        DetectSshVersionFree(ssh);
        return 0;
    }
    ssh = DetectSshVersionParse("lalala");
    if (ssh != NULL) {
        DetectSshVersionFree(ssh);
        return 0;
    }

    return 1;
}


#include "stream-tcp-reassemble.h"

/** \test Send a get request in three chunks + more data. */
static int DetectSshVersionTestDetect01(void)
{
    int result = 0;
    Flow f;
    uint8_t sshbuf1[] = "SSH-1.";
    uint32_t sshlen1 = sizeof(sshbuf1) - 1;
    uint8_t sshbuf2[] = "10-PuTTY_2.123" ;
    uint32_t sshlen2 = sizeof(sshbuf2) - 1;
    uint8_t sshbuf3[] = "\n";
    uint32_t sshlen3 = sizeof(sshbuf3) - 1;
    uint8_t sshbuf4[] = "whatever...";
    uint32_t sshlen4 = sizeof(sshbuf4) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_SSH;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ssh any any -> any any (msg:\"SSH\"; ssh.protoversion:1.10; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf1, sshlen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf2, sshlen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf3, sshlen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf4, sshlen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SshState *ssh_state = f.alstate;
    if (ssh_state == NULL) {
        printf("no ssh state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if ( !(PacketAlertCheck(p, 1))) {
        printf("Error, the sig should match: ");
        goto end;
    }

    result = 1;
end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    UTHFreePackets(&p, 1);

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    return result;
}

/** \test Send a get request in three chunks + more data. */
static int DetectSshVersionTestDetect02(void)
{
    int result = 0;
    Flow f;
    uint8_t sshbuf1[] = "SSH-1.";
    uint32_t sshlen1 = sizeof(sshbuf1) - 1;
    uint8_t sshbuf2[] = "99-PuTTY_2.123" ;
    uint32_t sshlen2 = sizeof(sshbuf2) - 1;
    uint8_t sshbuf3[] = "\n";
    uint32_t sshlen3 = sizeof(sshbuf3) - 1;
    uint8_t sshbuf4[] = "whatever...";
    uint32_t sshlen4 = sizeof(sshbuf4) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_SSH;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ssh any any -> any any (msg:\"SSH\"; ssh.protoversion:2_compat; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf1, sshlen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf2, sshlen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf3, sshlen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf4, sshlen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SshState *ssh_state = f.alstate;
    if (ssh_state == NULL) {
        printf("no ssh state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if ( !(PacketAlertCheck(p, 1))) {
        printf("Error, the sig should match: ");
        goto end;
    }

    result = 1;
end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    UTHFreePackets(&p, 1);
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    return result;
}

/** \test Send a get request in three chunks + more data. */
static int DetectSshVersionTestDetect03(void)
{
    int result = 0;
    Flow f;
    uint8_t sshbuf1[] = "SSH-1.";
    uint32_t sshlen1 = sizeof(sshbuf1) - 1;
    uint8_t sshbuf2[] = "7-PuTTY_2.123" ;
    uint32_t sshlen2 = sizeof(sshbuf2) - 1;
    uint8_t sshbuf3[] = "\n";
    uint32_t sshlen3 = sizeof(sshbuf3) - 1;
    uint8_t sshbuf4[] = "whatever...";
    uint32_t sshlen4 = sizeof(sshbuf4) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_SSH;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ssh any any -> any any (msg:\"SSH\"; ssh.protoversion:2_compat; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf1, sshlen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf2, sshlen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf3, sshlen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SSH, STREAM_TOSERVER, sshbuf4, sshlen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SshState *ssh_state = f.alstate;
    if (ssh_state == NULL) {
        printf("no ssh state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("Error, 1.7 version is not 2 compat, so the sig should not match: ");
        goto end;
    }

    result = 1;
end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    UTHFreePackets(&p, 1);
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    return result;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectSshVersion
 */
void DetectSshVersionRegisterTests(void)
{
#ifdef UNITTESTS /* UNITTESTS */
    UtRegisterTest("DetectSshVersionTestParse01", DetectSshVersionTestParse01, 1);
    UtRegisterTest("DetectSshVersionTestParse02", DetectSshVersionTestParse02, 1);
    UtRegisterTest("DetectSshVersionTestParse03", DetectSshVersionTestParse03, 1);
    UtRegisterTest("DetectSshVersionTestDetect01", DetectSshVersionTestDetect01, 1);
    UtRegisterTest("DetectSshVersionTestDetect02", DetectSshVersionTestDetect02, 1);
    UtRegisterTest("DetectSshVersionTestDetect03", DetectSshVersionTestDetect03, 1);
#endif /* UNITTESTS */
}

