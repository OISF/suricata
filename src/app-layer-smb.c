/* Copyright (C) 2017-2020 Open Information Security Foundation
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

#include "suricata-common.h"
#include "suricata.h"

#include "app-layer-protos.h"
#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"

#include "util-unittest.h"

#include "rust.h"
#include "app-layer-smb.h"
#include "util-misc.h"

#include "ippair-storage.h"
#include "app-layer-htp-file.h"
#include "app-layer-htp-range.h"

static StreamingBufferConfig sbcfg = STREAMING_BUFFER_CONFIG_INITIALIZER;
static SuricataFileContext sfc = { &sbcfg };

#ifdef UNITTESTS
static void SMBParserRegisterTests(void);
#endif

static IPPairStorageId g_ippair_smb_multi_id = { .id = -1 };

#define GUID_LEN 16

typedef struct SmbMultiIppairKey {
    uint8_t guid[GUID_LEN];
    uint64_t filesize;
    uint8_t *filename;
    uint16_t filename_len;
} SmbMultiIppairKey;

void SmbMultiSetFileSize(const Flow *f, const uint8_t *guid, uint64_t eof, const uint8_t *filename,
        uint16_t name_len)
{
    IPPair *ipp;
    Address ip_src, ip_dst;

    if (GetFlowAddresses(f, &ip_src, &ip_dst) == -1)
        return;
    ipp = IPPairGetIPPairFromHash(&ip_src, &ip_dst);
    if (ipp == NULL)
        return;

    SmbMultiIppairKey *key = IPPairGetStorageById(ipp, g_ippair_smb_multi_id);

    if (key) {
        // already a key
        if (memcmp(guid, key->guid, GUID_LEN) == 0) {
            // same guid, update only eof
            if (eof > key->filesize) {
                key->filesize = eof;
            }
            if (name_len > 0 && key->filename == NULL) {
                key->filename = SCMalloc(name_len);
                if (key->filename == NULL) {
                    SCFree(key);
                    goto end;
                }
                key->filename_len = name_len;
                memcpy(key->filename, filename, name_len);
            }
            goto end;
        } else {
            // different guid : keep old one TODOsmbmulti6 : handle multimulti ?
            goto end;
        }
    }
    // else
    key = SCCalloc(1, sizeof(SmbMultiIppairKey));
    if (key == NULL) {
        goto end;
    }

    memcpy(key->guid, guid, GUID_LEN);
    key->filesize = eof;
    if (name_len > 0) {
        key->filename = SCMalloc(name_len);
        if (key->filename == NULL) {
            SCFree(key);
            goto end;
        }
        key->filename_len = name_len;
        memcpy(key->filename, filename, name_len);
    }
    IPPairSetStorageById(ipp, g_ippair_smb_multi_id, key);
end:
    IPPairUnlock(ipp);
}

#define SMB_URL_PREFIX_LEN 6

HttpRangeContainerBlock *SmbMultiStartFileChunk(const Flow *f, const uint8_t *guid, uint16_t flags,
        FileContainer *fc, const StreamingBufferConfig *files_sbcfg, bool *added, uint64_t offset,
        uint32_t rlen, const uint8_t *data, uint32_t data_len)
{
    IPPair *ipp;
    Address ip_src, ip_dst;
    HttpRangeContainerBlock *r = NULL;

    if (GetFlowAddresses(f, &ip_src, &ip_dst) == -1)
        return NULL;
    ipp = IPPairLookupIPPairFromHash(&ip_src, &ip_dst);
    if (ipp == NULL)
        return NULL;

    SmbMultiIppairKey *key = IPPairGetStorageById(ipp, g_ippair_smb_multi_id);
    if (key == NULL) {
        key = SCCalloc(1, sizeof(SmbMultiIppairKey));
        if (key == NULL) {
            goto end;
        }
        memcpy(key->guid, guid, GUID_LEN);
        key->filesize = offset + rlen;
        IPPairSetStorageById(ipp, g_ippair_smb_multi_id, key);
    } else if (memcmp(guid, key->guid, GUID_LEN) != 0) {
        goto end;
    }
    FileContentRange fcr;
    if (offset > INT64_MAX || offset >= key->filesize || key->filesize > INT64_MAX) {
        goto end;
    }
    fcr.start = offset;
    fcr.size = key->filesize;
    if (offset + rlen > key->filesize) {
        fcr.end = key->filesize;
    } else {
        fcr.end = offset + rlen;
    }
    // TODOsmbmulmti4 should we only rely on ippair and have nothing global ?
    uint8_t hkey[GUID_LEN + SMB_URL_PREFIX_LEN];
    memcpy(hkey, "smb://", SMB_URL_PREFIX_LEN);
    memcpy(hkey + SMB_URL_PREFIX_LEN, guid, GUID_LEN);
    r = HttpRangeContainerOpenFile(hkey, GUID_LEN + SMB_URL_PREFIX_LEN, f, &fcr, files_sbcfg,
            key->filename, key->filename_len, flags, data, data_len);
    if (r) {
        if (data_len >= rlen) {
            *added = HTPFileCloseHandleRange(fc, flags, r, NULL, 0);
            HttpRangeFreeBlock(r);
            r = NULL;
        }
    }
end:
    IPPairUnlock(ipp);
    return r;
}

static void SmbMultiIppairFree(void *el)
{
    SCFree(el);
}

void RegisterSMBParsers(void)
{
    rs_smb_init(&sfc);
    rs_smb_register_parser();

    g_ippair_smb_multi_id =
            IPPairStorageRegister("smb.multi", sizeof(void *), NULL, SmbMultiIppairFree);

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_SMB, SMBParserRegisterTests);
#endif

    return;
}

#ifdef UNITTESTS
#include "stream-tcp.h"
#include "util-unittest-helper.h"

/** \test multi transactions and cleanup */
static int SMBParserTxCleanupTest(void)
{
    uint64_t ret[4];
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    StreamTcpInitConfig(true);
    TcpSession ssn;
    memset(&ssn, 0, sizeof(ssn));

    Flow *f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 445);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_SMB;

    char req_str[] ="\x00\x00\x00\x79\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00" \
                     "\x05\x00\xe0\x1e\x10\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00" \
                     "\x00\x00\x00\x00\x00\x00\x00\x00\x10\x72\xd2\x9f\x36\xc2\x08\x14" \
                     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                     "\x00\x00\x00\x00\x39\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00" \
                     "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00" \
                     "\x00\x00\x00\x00\x07\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00" \
                     "\x78\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    req_str[28] = 0x01;
    int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_SMB,
                                STREAM_TOSERVER | STREAM_START, (uint8_t *)req_str, sizeof(req_str));
    FAIL_IF_NOT(r == 0);
    req_str[28]++;
    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_SMB,
                                STREAM_TOSERVER, (uint8_t *)req_str, sizeof(req_str));
    FAIL_IF_NOT(r == 0);
    req_str[28]++;
    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_SMB,
                                STREAM_TOSERVER, (uint8_t *)req_str, sizeof(req_str));
    FAIL_IF_NOT(r == 0);
    req_str[28]++;
    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_SMB,
                                STREAM_TOSERVER, (uint8_t *)req_str, sizeof(req_str));
    FAIL_IF_NOT(r == 0);
    req_str[28]++;
    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_SMB,
                                STREAM_TOSERVER, (uint8_t *)req_str, sizeof(req_str));
    FAIL_IF_NOT(r == 0);
    req_str[28]++;
    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_SMB,
                                STREAM_TOSERVER, (uint8_t *)req_str, sizeof(req_str));
    FAIL_IF_NOT(r == 0);
    req_str[28]++;
    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_SMB,
                                STREAM_TOSERVER, (uint8_t *)req_str, sizeof(req_str));
    FAIL_IF_NOT(r == 0);
    req_str[28]++;
    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_SMB,
                                STREAM_TOSERVER, (uint8_t *)req_str, sizeof(req_str));
    FAIL_IF_NOT(r == 0);
    req_str[28]++;

    AppLayerParserTransactionsCleanup(f);
    UTHAppLayerParserStateGetIds(f->alparser, &ret[0], &ret[1], &ret[2], &ret[3]);
    FAIL_IF_NOT(ret[0] == 0); // inspect_id[0]
    FAIL_IF_NOT(ret[1] == 0); // inspect_id[1]
    FAIL_IF_NOT(ret[2] == 0); // log_id
    FAIL_IF_NOT(ret[3] == 0); // min_id

    char resp_str[] = "\x00\x00\x00\x98\xfe\x53\x4d\x42\x40\x00\x01\x00\x00\x00\x00\x00" \
                       "\x05\x00\x21\x00\x11\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00" \
                       "\x00\x00\x00\x00\x00\x00\x00\x00\x10\x72\xd2\x9f\x36\xc2\x08\x14" \
                       "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                       "\x00\x00\x00\x00\x59\x00\x00\x00\x01\x00\x00\x00\x48\x38\x40\xb3" \
                       "\x0f\xa8\xd3\x01\x84\x9a\x2b\x46\xf7\xa8\xd3\x01\x48\x38\x40\xb3" \
                       "\x0f\xa8\xd3\x01\x48\x38\x40\xb3\x0f\xa8\xd3\x01\x00\x00\x00\x00" \
                       "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00" \
                       "\x00\x00\x00\x00\x9e\x8f\xb8\x91\x00\x00\x00\x00\x01\x5b\x11\xbb" \
                       "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    resp_str[28] = 0x01;
    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_SMB,
                                STREAM_TOCLIENT | STREAM_START, (uint8_t *)resp_str, sizeof(resp_str));
    FAIL_IF_NOT(r == 0);
    resp_str[28] = 0x04;
    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_SMB,
                                STREAM_TOCLIENT, (uint8_t *)resp_str, sizeof(resp_str));
    FAIL_IF_NOT(r == 0);
    resp_str[28] = 0x05;
    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_SMB,
                                STREAM_TOCLIENT, (uint8_t *)resp_str, sizeof(resp_str));
    FAIL_IF_NOT(r == 0);
    resp_str[28] = 0x06;
    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_SMB,
                                STREAM_TOCLIENT, (uint8_t *)resp_str, sizeof(resp_str));
    FAIL_IF_NOT(r == 0);
    resp_str[28] = 0x08;
    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_SMB,
                                STREAM_TOCLIENT, (uint8_t *)resp_str, sizeof(resp_str));
    FAIL_IF_NOT(r == 0);
    resp_str[28] = 0x02;
    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_SMB,
                                STREAM_TOCLIENT, (uint8_t *)resp_str, sizeof(resp_str));
    FAIL_IF_NOT(r == 0);
    resp_str[28] = 0x07;
    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_SMB,
                                STREAM_TOCLIENT, (uint8_t *)resp_str, sizeof(resp_str));
    FAIL_IF_NOT(r == 0);
    AppLayerParserTransactionsCleanup(f);

    UTHAppLayerParserStateGetIds(f->alparser, &ret[0], &ret[1], &ret[2], &ret[3]);
    FAIL_IF_NOT(ret[0] == 2); // inspect_id[0]
    FAIL_IF_NOT(ret[1] == 2); // inspect_id[1]
    FAIL_IF_NOT(ret[2] == 2); // log_id
    FAIL_IF_NOT(ret[3] == 2); // min_id

    resp_str[28] = 0x03;
    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_SMB,
                                STREAM_TOCLIENT, (uint8_t *)resp_str, sizeof(resp_str));
    FAIL_IF_NOT(r == 0);
    AppLayerParserTransactionsCleanup(f);

    UTHAppLayerParserStateGetIds(f->alparser, &ret[0], &ret[1], &ret[2], &ret[3]);
    FAIL_IF_NOT(ret[0] == 8); // inspect_id[0]
    FAIL_IF_NOT(ret[1] == 8); // inspect_id[1]
    FAIL_IF_NOT(ret[2] == 8); // log_id
    FAIL_IF_NOT(ret[3] == 8); // min_id

    req_str[28] = 0x09;
    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_SMB,
                                STREAM_TOSERVER | STREAM_EOF, (uint8_t *)req_str, sizeof(req_str));
    FAIL_IF_NOT(r == 0);
    AppLayerParserTransactionsCleanup(f);

    UTHAppLayerParserStateGetIds(f->alparser, &ret[0], &ret[1], &ret[2], &ret[3]);
    FAIL_IF_NOT(ret[0] == 8); // inspect_id[0] not updated by ..Cleanup() until full tx is done
    FAIL_IF_NOT(ret[1] == 8); // inspect_id[1]
    FAIL_IF_NOT(ret[2] == 8); // log_id
    FAIL_IF_NOT(ret[3] == 8); // min_id

    resp_str[28] = 0x09;
    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_SMB,
                                STREAM_TOCLIENT | STREAM_EOF, (uint8_t *)resp_str, sizeof(resp_str));
    FAIL_IF_NOT(r == 0);
    AppLayerParserTransactionsCleanup(f);

    UTHAppLayerParserStateGetIds(f->alparser, &ret[0], &ret[1], &ret[2], &ret[3]);
    FAIL_IF_NOT(ret[0] == 9); // inspect_id[0]
    FAIL_IF_NOT(ret[1] == 9); // inspect_id[1]
    FAIL_IF_NOT(ret[2] == 9); // log_id
    FAIL_IF_NOT(ret[3] == 9); // min_id

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);

    PASS;
}

static void SMBParserRegisterTests(void)
{
    UtRegisterTest("SMBParserTxCleanupTest", SMBParserTxCleanupTest);
}

#endif /* UNITTESTS */
