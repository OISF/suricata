/* Copyright (C) 2017-2022 Open Information Security Foundation
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
 * \author Giuseppe Longo <glongo@stamus-networks.com>
 *
 * Detection engine helper functions
 */

#include "suricata-common.h"
#include "suricata.h"
#include "detect.h"
#include "util-detect.h"

/**
 * \brief Allocate SigString list member
 *
 * \retval Pointer to SigString
 */
SigString *SigStringAlloc(void)
{
    SigString *sigstr = SCCalloc(1, sizeof(SigString));
    if (unlikely(sigstr == NULL))
        return NULL;

    sigstr->line = 0;

    return sigstr;
}

/**
 * \brief Assigns the filename, signature, lineno to SigString list member
 *
 * \param sig pointer to SigString
 * \param sig_file filename that contains the signature
 * \param sig_str signature in string format
 * \param sig_error signature parsing error
 * \param line line line number
 *
 * \retval 1 on success 0 on failure
 */
static int SigStringAddSig(SigString *sig, const char *sig_file,
                           const char *sig_str, const char *sig_error,
                           int line)
{
    if (sig_file == NULL || sig_str == NULL) {
        return 0;
    }

    sig->filename = SCStrdup(sig_file);
    if (sig->filename == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        return 0;
    }

    sig->sig_str = SCStrdup(sig_str);
    if (sig->sig_str == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        SCFree(sig->filename);
        return 0;
    }

    if (sig_error) {
        sig->sig_error = SCStrdup(sig_error);
        if (sig->sig_error == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            SCFree(sig->filename);
            SCFree(sig->sig_str);
            return 0;
        }
    }

    sig->line = line;

    return 1;
}

/**
 * \brief Append a new list member to SigString list
 *
 * \param list pointer to the start of the SigString list
 * \param sig_file filename that contains the signature
 * \param sig_str signature in string format
 * \param line line line number
 *
 * \retval 1 on success 0 on failure
 */
int SigStringAppend(SigFileLoaderStat *sig_stats, const char *sig_file,
                    const char *sig_str, const char *sig_error, int line)
{
    SigString *item = SigStringAlloc();
    if (item == NULL) {
        return 0;
    }

    if (!SigStringAddSig(item, sig_file, sig_str, sig_error, line)) {
        SCFree(item);
        return 0;
    }

    TAILQ_INSERT_TAIL(&sig_stats->failed_sigs, item, next);

    return 1;
}
