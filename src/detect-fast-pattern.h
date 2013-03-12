/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __DETECT_FAST_PATTERN_H__
#define __DETECT_FAST_PATTERN_H__

typedef struct SCFPSupportSMList_ {
    /* the list id.  Have a look at Signature->sm_lists[] */
    int list_id;
    int priority;

    struct SCFPSupportSMList_ *next;
} SCFPSupportSMList;

extern SCFPSupportSMList *sm_fp_support_smlist_list;

/**
 * \brief Checks if a particular list(Signature->sm_lists[]) is in the list
 *        of lists that need to be searched for a keyword that has fp support.
 *
 * \param list_id The list id.
 *
 * \retval 1 If supported.
 * \retval 0 If not.
 */
static inline int FastPatternSupportEnabledForSigMatchList(int list_id)
{
    if (sm_fp_support_smlist_list == NULL)
        return 0;

    SCFPSupportSMList *tmp_smlist_fp = sm_fp_support_smlist_list;
    while (tmp_smlist_fp != NULL) {
        if (tmp_smlist_fp->list_id == list_id)
            return 1;

        tmp_smlist_fp = tmp_smlist_fp->next;
    }

    return 0;
}

void SupportFastPatternForSigMatchTypes(void);

void DetectFastPatternRegister(void);

#endif /* __DETECT_FAST_PATTERN_H__ */

