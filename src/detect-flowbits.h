/* Copyright (C) 2007-2025 Open Information Security Foundation
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
 *  \author Victor Julien <victor@inliniac.net>
 *  \author Breno Silva <breno.silva@gmail.com>
 */

#ifndef SURICATA_DETECT_FLOWBITS_H
#define SURICATA_DETECT_FLOWBITS_H

#define DETECT_FLOWBITS_CMD_SET      0
#define DETECT_FLOWBITS_CMD_TOGGLE   1
#define DETECT_FLOWBITS_CMD_UNSET    2
#define DETECT_FLOWBITS_CMD_ISNOTSET 3
#define DETECT_FLOWBITS_CMD_ISSET    4
#define DETECT_FLOWBITS_CMD_MAX      5

struct FBAnalyzer {
    struct FBAnalyze *array;
    uint32_t array_size;
};

struct FBAnalyze {
    uint16_t cnts[DETECT_FLOWBITS_CMD_MAX];
    uint16_t state_cnts[DETECT_FLOWBITS_CMD_MAX];

    uint32_t *set_iids;
    uint32_t set_iids_idx;
    uint32_t set_iids_size;

    uint32_t *isset_iids;
    uint32_t isset_iids_idx;
    uint32_t isset_iids_size;

    uint32_t *isnotset_iids;
    uint32_t isnotset_iids_idx;
    uint32_t isnotset_iids_size;

    uint32_t *unset_iids;
    uint32_t unset_iids_idx;
    uint32_t unset_iids_size;

    uint32_t *toggle_iids;
    uint32_t toggle_iids_idx;
    uint32_t toggle_iids_size;
};

typedef struct DetectFlowbitsData_ {
    uint32_t idx;
    uint8_t cmd;
    uint8_t or_list_size;
    /** Flag to trigger post rule match prefilter following a 'set' match. */
    bool post_rule_match_prefilter; /**< set/toggle command should trigger post-rule-match
                                       "prefilter" */
    uint32_t *or_list;
} DetectFlowbitsData;

/* prototypes */
void DetectFlowbitsRegister (void);

#endif /* SURICATA_DETECT_FLOWBITS_H */
