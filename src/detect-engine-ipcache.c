/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Address part of the detection engine.
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-engine-ip.h"
#include "detect-engine-ipcache.h"
#include "util-debug.h"
#include "util-hash-lookup3.h"

static uint32_t DetectAddressCacheHashFunc(HashListTable *ht, void *data, uint16_t datalen)
{
    const DetectAddressCache *map = (DetectAddressCache *)data;
    uint32_t hash = hashlittle_safe(map->string, strlen(map->string), 0);
    hash %= ht->array_size;
    return hash;
}

static char DetectAddressCacheCompareFunc(void *data1, uint16_t len1, void *data2, uint16_t len2)
{
    DetectAddressCache *map1 = (DetectAddressCache *)data1;
    DetectAddressCache *map2 = (DetectAddressCache *)data2;
    int r = (strcmp(map1->string, map2->string) == 0);
    return r;
}

static void DetectAddressCacheFreeFunc(void *data)
{
    DetectAddressCache *map = (DetectAddressCache *)data;
    if (map != NULL) {
        DetectAddressesClear(&map->a);
        SCFree(map->string);
    }
    SCFree(map);
}

int DetectAddressCacheInit(DetectEngineCtx *de_ctx)
{
    de_ctx->address_table = HashListTableInit(4096, DetectAddressCacheHashFunc,
            DetectAddressCacheCompareFunc, DetectAddressCacheFreeFunc);
    if (de_ctx->address_table == NULL)
        return -1;

    return 0;
}

void DetectAddressCacheFree(DetectEngineCtx *de_ctx)
{
    if (de_ctx->address_table == NULL)
        return;

    HashListTableFree(de_ctx->address_table);
    de_ctx->address_table = NULL;
    return;
}

int DetectAddressCacheAdd(
        DetectEngineCtx *de_ctx, const char *string, struct DetectAddresses address)
{
    DetectAddressCache *map = SCCalloc(1, sizeof(*map));
    if (map == NULL)
        return -1;

    map->string = SCStrdup(string);
    if (map->string == NULL) {
        SCFree(map);
        return -1;
    }
    map->a = address;

    BUG_ON(HashListTableAdd(de_ctx->address_table, (void *)map, 0) != 0);
    return 0;
}

const DetectAddressCache *DetectAddressCacheLookup(DetectEngineCtx *de_ctx, const char *string)
{
    DetectAddressCache map = { (char *)string,
        .a = { .ipv4 = SC_RADIX4_TREE_INITIALIZER, .ipv6 = SC_RADIX6_TREE_INITIALIZER } };

    const DetectAddressCache *res = HashListTableLookup(de_ctx->address_table, &map, 0);
    return res;
}
