/* Copyright (C) 2024 Open Information Security Foundation
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
 * \author Jeff Lucovsky <jlucovsky@oisf.net>
 */

#ifndef SURICATA_DETECT_TRANSFORM_LUAXFORM_H
#define SURICATA_DETECT_TRANSFORM_LUAXFORM_H

/* prototypes */
void DetectTransformLuaxformRegister(void);

#define LUAXFORM_MAX_ARGS 10

typedef struct DetectLuaxformData {
    int thread_ctx_id;
    int allow_restricted_functions;
    int arg_count;
    uint64_t alloc_limit;
    uint64_t instruction_limit;
    char *filename;
    char *copystr;
    char *args[LUAXFORM_MAX_ARGS];
} DetectLuaxformData;

typedef struct DetectLuaxformThreadData {
    lua_State *luastate;
} DetectLuaxformThreadData;

#endif /* SURICATA_DETECT_TRANSFORM_LUAXFORM_H */
