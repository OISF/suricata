/* Copyright (C) 2007-2021 Open Information Security Foundation
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
 * \author Tom DeCanio <td@npulsetech.com>
 */

#ifndef SURICATA_OUTPUT_JSON_H
#define SURICATA_OUTPUT_JSON_H

#include "suricata-common.h"
#include "util-buffer.h"
#include "util-logopenfile.h"
#include "output.h"
#include "output-eve-bindgen.h"

#include "app-layer-htp-xff.h"

void OutputJsonRegister(void);

#define JSON_ADDR_LEN 46
#define JSON_PROTO_LEN 16

/* A struct to contain address info for rendering to JSON. */
typedef struct JsonAddrInfo_ {
    char src_ip[JSON_ADDR_LEN];
    char dst_ip[JSON_ADDR_LEN];
    Port sp;
    Port dp;
    char proto[JSON_PROTO_LEN];
    // Ports are logged only when provided by the transport protocol.
    bool log_port;
} JsonAddrInfo;

extern const JsonAddrInfo json_addr_info_zero;

void JsonAddrInfoInit(const Packet *p, enum SCOutputJsonLogDirection dir, JsonAddrInfo *addr);

/* Suggested output buffer size */
#define JSON_OUTPUT_BUFFER_SIZE 65535

/* helper struct for OutputJSONMemBufferCallback */
typedef struct OutputJSONMemBufferWrapper_ {
    MemBuffer **buffer; /**< buffer to use & expand as needed */
    uint32_t expand_by; /**< expand by this size */
} OutputJSONMemBufferWrapper;

typedef struct OutputJsonCommonSettings_ {
    bool include_metadata;
    bool include_community_id;
    bool include_ethernet;
    bool include_suricata_version;
    uint16_t community_id_seed;
} OutputJsonCommonSettings;

/*
 * Global configuration context data
 */
typedef struct OutputJsonCtx_ {
    LogFileCtx *file_ctx;
    enum LogFileType json_out;
    OutputJsonCommonSettings cfg;
    HttpXFFCfg *xff_cfg;
    SCEveFileType *filetype;
} OutputJsonCtx;

typedef struct OutputJsonThreadCtx_ {
    OutputJsonCtx *ctx;
    LogFileCtx *file_ctx;
    MemBuffer *buffer;
    bool too_large_warning;
} OutputJsonThreadCtx;

json_t *SCJsonString(const char *val);

void CreateEveFlowId(SCJsonBuilder *js, const Flow *f);
void EveFileInfo(SCJsonBuilder *js, const File *file, const uint64_t tx_id, const uint16_t flags);
void EveTcpFlags(uint8_t flags, SCJsonBuilder *js);
void EvePacket(const Packet *p, SCJsonBuilder *js, uint32_t max_length);
SCJsonBuilder *CreateEveHeader(const Packet *p, enum SCOutputJsonLogDirection dir,
        const char *event_type, JsonAddrInfo *addr, OutputJsonCtx *eve_ctx);
SCJsonBuilder *CreateEveHeaderWithTxId(const Packet *p, enum SCOutputJsonLogDirection dir,
        const char *event_type, JsonAddrInfo *addr, uint64_t tx_id, OutputJsonCtx *eve_ctx);
int OutputJSONBuffer(json_t *js, LogFileCtx *file_ctx, MemBuffer **buffer);
void OutputJsonBuilderBuffer(
        ThreadVars *tv, const Packet *p, Flow *f, SCJsonBuilder *js, OutputJsonThreadCtx *ctx);
OutputInitResult OutputJsonInitCtx(SCConfNode *);

OutputInitResult OutputJsonLogInitSub(SCConfNode *conf, OutputCtx *parent_ctx);
TmEcode JsonLogThreadInit(ThreadVars *t, const void *initdata, void **data);
TmEcode JsonLogThreadDeinit(ThreadVars *t, void *data);

void EveAddCommonOptions(const OutputJsonCommonSettings *cfg, const Packet *p, const Flow *f,
        SCJsonBuilder *js, enum SCOutputJsonLogDirection dir);
int OutputJsonLogFlush(ThreadVars *tv, void *thread_data, const Packet *p);
void EveAddMetadata(const Packet *p, const Flow *f, SCJsonBuilder *js);

int OutputJSONMemBufferCallback(const char *str, size_t size, void *data);

OutputJsonThreadCtx *CreateEveThreadCtx(ThreadVars *t, OutputJsonCtx *ctx);
void FreeEveThreadCtx(OutputJsonThreadCtx *ctx);
void JSONFormatAndAddMACAddr(SCJsonBuilder *js, const char *key, const uint8_t *val, bool is_array);
void OutputJsonFlush(OutputJsonThreadCtx *ctx);

#endif /* SURICATA_OUTPUT_JSON_H */
