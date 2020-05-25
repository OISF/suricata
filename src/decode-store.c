/* Copyright (C) 2007-2019 Open Information Security Foundation
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
#include "conf.h"
#include "decode.h"
#include "decode-store.h"

static inline struct DecodeStore *GetActiveStore(struct DecodeStore *s)
{
    while (s && s->is_full) {
        s = s->next;
    }
    return s;
}

static inline struct DecodeStore *GetNewStore(void)
{
    struct DecodeStore *s = SCCalloc(1, sizeof(*s));
    if (s == NULL)
        return NULL;
    return s;
}

static inline void Copy(struct DecodeStore *s, const uint8_t *data, size_t data_size)
{
    memcpy(s->data+s->data_offset, data, data_size);
    s->data_offset += data_size;
    s->is_full = (s->data_offset == DECODE_STORE_SIZE - 1);
}

static void PrintInfo(struct DecodeStore *s)
{
    SCLogDebug("store %p used %u out of %u", s, s->data_offset, DECODE_STORE_SIZE);
}

static void Append(Packet *p, uint8_t *data, size_t data_size)
{
    SCLogDebug("start");
    struct DecodeStore *s = GetActiveStore(&p->decode_store);
    SCLogDebug("s %p", s);
    if (!s) {
        s = GetNewStore();
        if (!s) {
            // SET EVENT?
            return;
        }
    }
    SCLogDebug("s %p", s);
    if (data_size + s->data_offset < DECODE_STORE_SIZE) {
        Copy(s, data, data_size);
        SCLogDebug("data fits, done");
        PrintInfo(s);
        return;
    }
    SCLogDebug("data does not fit, get additional store");

    s->data[s->data_offset] = DECODE_STORE_TYPE_NEXT;
    s->is_full = true;

    s->next = GetNewStore();
    if (!s->next) {
        // SET EVENT?
        return;
    }
    s = s->next;
    Copy(s, data, data_size);
    SCLogDebug("got additional store. Done");
    PrintInfo(s);
}


typedef union DecodeStoreBuiltinVLAN {
    struct {
        uint16_t type:4;
        uint16_t value:12;
    };
    uint8_t x[2];
} DecodeStoreBuiltinVLAN;

typedef union DecodeStoreBuiltinMPLS {
    struct {
        uint32_t type:4;
        uint32_t pad:4;
        uint32_t value:24;
    };
    uint8_t x[4];
} DecodeStoreBuiltinMPLS;

void DecodeStoreAddVLAN(Packet *p, const uint16_t vlan_id)
{
    DecodeStoreBuiltinVLAN v = {
        .type = DECODE_STORE_TYPE_VLAN, .value = vlan_id
    };
    Append(p, v.x, sizeof(v.x));
    SCLogDebug("id %u added (v.type %u v.value %u)", vlan_id, v.type, v.value);
}

void DecodeStoreAddMPLS(Packet *p, const uint32_t label)
{
    DecodeStoreBuiltinMPLS v = {
        .type = DECODE_STORE_TYPE_MPLS, .value = label
    };
    Append(p, v.x, sizeof(v.x));
    SCLogDebug("label %u added (v.type %u v.value %u)", label, v.type, v.value);
}

typedef struct DecodeStoreBuiltinTLV {
    uint8_t type:4;
    uint8_t pad:4;
    uint8_t etype;
    uint8_t len;
} DecodeStoreBuiltinTLV;

int DecodeStoreAddTLV(Packet *p, uint8_t etype, const uint8_t *data, uint8_t data_len)
{
    if (data_len + sizeof(DecodeStoreBuiltinTLV) >= (size_t)DECODE_STORE_SIZE)
        return -EINVAL;

    const size_t buf_size = sizeof(DecodeStoreBuiltinTLV) + data_len;
    uint8_t buf[buf_size];
    DecodeStoreBuiltinTLV hdr = {
        .type = DECODE_STORE_TYPE_TLV, .pad = 0, .etype = etype, .len = data_len + 3
    };
    memcpy(buf, &hdr, sizeof(hdr));
    memcpy(buf+sizeof(hdr), data, data_len);
    Append(p, buf, buf_size);
    SCLogDebug("TLV added %u datalen %u total %u", etype, data_len, hdr.len);
    return 0;
}

static inline int GetTypeAndSize(const uint8_t *data, uint8_t size, uint8_t *type, uint8_t *out_size)
{
    assert(size >= 1);

    *type = *data & 0x0f;
    *out_size = 0;

    switch (*type) {
        case DECODE_STORE_TYPE_VLAN:
            *out_size = 2;
            break;
        case DECODE_STORE_TYPE_MPLS:
            *out_size = 4;
            break;
        case DECODE_STORE_TYPE_NEXT:
            *out_size = 1;
            break;
        case DECODE_STORE_TYPE_TLV: {
            DecodeStoreBuiltinTLV hdr;
            memcpy(&hdr, data, sizeof(hdr));
            *out_size = hdr.len;
            break;
        }
    }
    if (*out_size > 0 && *out_size <= size)
        return 1;
    return 0;
}

#define LOOP_TOP(stype)                                                     \
    int i = 0;                                                              \
    for (const struct DecodeStore *s = &p->decode_store;                    \
         s != NULL; s = s->next) {                                          \
        uint8_t offset = 0;                                                 \
        while (offset < s->data_offset) {                                   \
            uint8_t type, size;                                             \
            if (GetTypeAndSize(&s->data[offset], s->data_offset - offset,   \
                               &type, &size) != 1)                          \
                return -1;                                                  \
                                                                            \
            if (type == (stype)) {                                          \
                if (i == n) {

#define LOOP_BOT                                                            \
                    return 1;                                               \
                }                                                           \
                i++;                                                        \
            }                                                               \
            offset += size;                                                 \
        }                                                                   \
    }                                                                       \
    return 0;

int DecodeStoreGetVLAN(const Packet *p, int n, uint16_t *vlan_id)
{
    LOOP_TOP(DECODE_STORE_TYPE_VLAN);
    DecodeStoreBuiltinVLAN v;
    memcpy(&v, &s->data[offset], sizeof(v));
    *vlan_id = v.value;
    LOOP_BOT
}

int DecodeStoreGetMPLS(const Packet *p, int n, uint32_t *label)
{
    LOOP_TOP(DECODE_STORE_TYPE_MPLS);
    DecodeStoreBuiltinMPLS v;
    memcpy(&v, &s->data[offset], sizeof(v));
    *label = v.value;
    LOOP_BOT
}

int DecodeStoreGetTLV(const Packet *p, int n, const uint8_t etype,
        uint8_t **data, uint8_t *data_len, uint8_t data_size)
{
    LOOP_TOP(DECODE_STORE_TYPE_TLV);
    DecodeStoreBuiltinTLV hdr;
    memcpy(&hdr, &s->data[offset], sizeof(hdr));
    if (hdr.etype == etype) {
        if (hdr.len > data_size)
            return -ENOBUFS;
        memcpy(*data, &s->data[offset + sizeof(hdr)], hdr.len);
        *data_len = hdr.len;
    }
    LOOP_BOT
}

#undef LOOP_TOP
#undef LOOP_BOT

static inline void FreeDynamic(struct DecodeStore *s)
{
    while (s != NULL) {
        struct DecodeStore *next = s->next;
        SCFree(s);
        s = next;
    }
}

void DecodeStoreCleanup(Packet *p)
{
    struct DecodeStore *s = &p->decode_store;
    if (s->data_offset == 0) {
        return;
    }

    s->data_offset = 0;
    s->is_full = false;
    FreeDynamic(s->next);
    s->next = NULL;
}

void DecodeStoreIterate(const Packet *p,
        void (*Callback)(void *cb_data, const uint8_t type, const uint8_t etype, const uint8_t size, const uint8_t *data),
        void *cb_data)
{
    for (const struct DecodeStore *s = &p->decode_store; s != NULL; s = s->next) {
        uint8_t offset = 0;
        while (offset < s->data_offset) {
            uint8_t type, size;
            if (GetTypeAndSize(&s->data[offset], s->data_offset - offset, &type, &size) != 1)
                break;

            switch (type) {
                case DECODE_STORE_TYPE_MPLS: {
                    SCLogDebug("MPLS type %d size %u", type, size);
                    DecodeStoreBuiltinMPLS v;
                    memcpy(&v, &s->data[offset], sizeof(v));
                    union {
                        uint32_t label;
                        uint8_t data[4];
                    } u;
                    u.label = v.value;
                    Callback(cb_data, type, 0, 4, u.data);
                    break;
                }
                case DECODE_STORE_TYPE_VLAN: {
                    SCLogDebug("VLAN type %d size %u", type, size);
                    DecodeStoreBuiltinVLAN v;
                    memcpy(&v, &s->data[offset], sizeof(v));
                    union {
                        uint16_t vlan_id;
                        uint8_t data[2];
                    } u;
                    u.vlan_id = v.value;
                    Callback(cb_data, type, 0, 2, u.data);
                    break;
                }
                case DECODE_STORE_TYPE_TLV: {
                    const uint8_t *data = &s->data[offset];
                    DecodeStoreBuiltinTLV v;
                    memcpy(&v, &s->data[offset], sizeof(v));
                    SCLogDebug("TLV type %d size %u", type, size);
                    Callback(cb_data, type, v.etype, v.len - 3, data + 3);
                    break;
                }
                case DECODE_STORE_TYPE_NEXT:
                    SCLogNotice("NEXT type %d size %u", type, size);
                    break;
                default:
                    SCLogNotice("type %d size %u", type, size);
                    break;
            }

            offset += size;
        }
    }
}


// TODO dumper/iterator for building EVE obj

// TODO for TLV have global registery for id's.

// TODO instead of true TLV, use types? E.g. u8, u16, u32, u64? -> these we can print in json w/o special code
