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
 * \author  Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 * File to drop the engine capabilities using libcap-ng by
 * Steve Grubb
 */

#ifndef OS_WIN32

#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/stat.h>
#include "suricata-common.h"
#include "util-debug.h"
#include "suricata.h"

#include "util-privs.h"

#ifdef HAVE_LIBCAP_NG

#include <cap-ng.h>
#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif
#include "threadvars.h"
#include "util-cpu.h"
#include "runmodes.h"

/** flag indicating if we'll be using caps */
extern int sc_set_caps;

/** our current runmode */
extern int run_mode;

/**
 * \brief   Drop the previliges of the main thread
 */
void SCDropMainThreadCaps(uint32_t userid, uint32_t groupid)
{
    if (sc_set_caps == FALSE)
        return;

    capng_clear(CAPNG_SELECT_BOTH);

    switch (run_mode) {
        case RUNMODE_PCAP_DEV:
        case RUNMODE_AFP_DEV:
            capng_updatev(CAPNG_ADD, CAPNG_EFFECTIVE|CAPNG_PERMITTED,
                    CAP_NET_RAW,            /* needed for pcap live mode */
                    CAP_SYS_NICE,
                    CAP_NET_ADMIN,
                    -1);
            break;
        case RUNMODE_PFRING:
            capng_updatev(CAPNG_ADD, CAPNG_EFFECTIVE|CAPNG_PERMITTED,
                    CAP_NET_ADMIN, CAP_NET_RAW, CAP_SYS_NICE,
                    -1);
            break;
        case RUNMODE_NFQ:
            capng_updatev(CAPNG_ADD, CAPNG_EFFECTIVE|CAPNG_PERMITTED,
                    CAP_NET_ADMIN,          /* needed for nfqueue inline mode */
                    CAP_SYS_NICE,
                    -1);
            break;
    }

    if (capng_change_id(userid, groupid, CAPNG_DROP_SUPP_GRP |
            CAPNG_CLEAR_BOUNDING) < 0)
    {
        SCLogError(SC_ERR_CHANGING_CAPS_FAILED, "capng_change_id for main thread"
                " failed");
        exit(EXIT_FAILURE);
    }

    SCLogInfo("dropped the caps for main thread");
}

void SCDropCaps(ThreadVars *tv)
{
#if 0
    capng_clear(CAPNG_SELECT_BOTH);
    capng_apply(CAPNG_SELECT_BOTH);
    if (tv->cap_flags & SC_CAP_IPC_LOCK) {
        capng_update(CAPNG_ADD, (capng_type_t) (CAPNG_EFFECTIVE | CAPNG_PERMITTED), CAP_IPC_LOCK);
        capng_apply(CAPNG_SELECT_CAPS);
        SCLogDebug("For thread \"%s\" CAP_IPC_LOCK has been set", tv->name);
    }
    if (tv->cap_flags & SC_CAP_NET_ADMIN) {
        capng_update(CAPNG_ADD, (capng_type_t) (CAPNG_EFFECTIVE | CAPNG_PERMITTED), CAP_NET_ADMIN);
        capng_apply(CAPNG_SELECT_CAPS);
        SCLogDebug("For thread \"%s\" CAP_NET_ADMIN has been set", tv->name);
    }
    if (tv->cap_flags & SC_CAP_NET_BIND_SERVICE) {
        capng_update(CAPNG_ADD, (capng_type_t) (CAPNG_EFFECTIVE | CAPNG_PERMITTED), CAP_NET_BIND_SERVICE);
        capng_apply(CAPNG_SELECT_CAPS);
        SCLogDebug("For thread \"%s\" CAP_NET_BIND_SERVICE has been set", tv->name);
    }
    if (tv->cap_flags & SC_CAP_NET_BROADCAST) {
        capng_update(CAPNG_ADD, (capng_type_t) (CAPNG_EFFECTIVE | CAPNG_PERMITTED), CAP_NET_BROADCAST);
        capng_apply(CAPNG_SELECT_CAPS);
        SCLogDebug("For thread \"%s\" CAP_NET_BROADCAST has been set", tv->name);
    }
    if (tv->cap_flags & SC_CAP_NET_RAW) {
        capng_update(CAPNG_ADD, (capng_type_t) (CAPNG_EFFECTIVE | CAPNG_PERMITTED), CAP_NET_RAW);
        capng_apply(CAPNG_SELECT_CAPS);
        SCLogDebug("For thread \"%s\" CAP_NET_RAW has been set", tv->name);
    }
    if (tv->cap_flags & SC_CAP_SYS_ADMIN) {
        capng_update(CAPNG_ADD, (capng_type_t) (CAPNG_EFFECTIVE | CAPNG_PERMITTED), CAP_SYS_ADMIN);
        capng_apply(CAPNG_SELECT_CAPS);
        SCLogDebug("For thread \"%s\" CAP_SYS_ADMIN has been set", tv->name);
    }
    if (tv->cap_flags & SC_CAP_SYS_RAW_IO) {
        capng_update(CAPNG_ADD, (capng_type_t) (CAPNG_EFFECTIVE | CAPNG_PERMITTED), CAP_SYS_RAWIO);
        capng_apply(CAPNG_SELECT_CAPS);
        SCLogDebug("For thread \"%s\" CAP_SYS_RAWIO has been set", tv->name);
    }
#endif
}

#endif /* HAVE_LIBCAP_NG */

/**
 * \brief   Function to get the user and group ID from the specified user name
 *
 * \param   user_name   pointer to the given user name
 * \param   uid         pointer to the user id in which result will be stored
 * \param   gid         pointer to the group id in which result will be stored
 *
 * \retval  upon success it return 0
 */
int SCGetUserID(const char *user_name, const char *group_name, uint32_t *uid, uint32_t *gid)
{
    uint32_t userid = 0;
    uint32_t groupid = 0;
    struct passwd *pw;

    /* Get the user ID */
    if (isdigit((unsigned char)user_name[0]) != 0) {
        userid = atoi(user_name);
        pw = getpwuid(userid);
       if (pw == NULL) {
            SCLogError(SC_ERR_UID_FAILED, "unable to get the user ID, "
                    "check if user exist!!");
            exit(EXIT_FAILURE);
        }
    } else {
        pw = getpwnam(user_name);
        if (pw == NULL) {
            SCLogError(SC_ERR_UID_FAILED, "unable to get the user ID, "
                    "check if user exist!!");
            exit(EXIT_FAILURE);
        }
        userid = pw->pw_uid;
    }

    /* Get the group ID */
    if (group_name != NULL) {
        struct group *gp;

        if (isdigit((unsigned char)group_name[0]) != 0) {
            groupid = atoi(group_name);
        } else {
            gp = getgrnam(group_name);
            if (gp == NULL) {
                SCLogError(SC_ERR_GID_FAILED, "unable to get the group"
                        " ID, check if group exist!!");
                exit(EXIT_FAILURE);
            }
            groupid = gp->gr_gid;
        }
    } else {
        groupid = pw->pw_gid;
    }

    /* close the group database */
    endgrent();
    /* close the user database */
    endpwent();

    *uid = userid;
    *gid = groupid;

    return 0;
}

/**
 * \brief   Function to get the group ID from the specified group name
 *
 * \param   group_name  pointer to the given group name
 * \param   gid         pointer to the group id in which result will be stored
 *
 * \retval  upon success it return 0
 */
int SCGetGroupID(const char *group_name, uint32_t *gid)
{
    uint32_t grpid = 0;
    struct group *gp;

    /* Get the group ID */
    if (isdigit((unsigned char)group_name[0]) != 0) {
        grpid = atoi(group_name);
    } else {
        gp = getgrnam(group_name);
        if (gp == NULL) {
            SCLogError(SC_ERR_GID_FAILED, "unable to get the group ID,"
                    " check if group exist!!");
            exit(EXIT_FAILURE);
        }
        grpid = gp->gr_gid;
    }

    /* close the group database */
    endgrent();

    *gid = grpid;

    return 0;
}

/**
 * \brief   Check if requested file access is allowed for arbitrary user, file and access mode
 *          (pure, no side effects)
 *
 * \param   asked_uid      The uid to check for
 * \param   asked_gids     Array of the gids to check for
 * \param   gid_count      The number gids at the supplied gid array address
 * \param   file_stat_struct   Pointer to the stat() return struct of the file to check for
 * \param   requested_access   The requested access mode
 *                             Use access type macro symbols from unistd.h, like in man 2 access
 *
 * \retval  Boolean. True if requested access is allowed. False otherwise
 */
bool SCCheckArbitraryFileAccess(const uid_t asked_uid,
                                const gid_t * const asked_gids,
                                const int gid_count,
                                struct stat const * const file_stat_struct,
                                const int requested_permissions)
{
    /* Step 1: Prepare Bitmasks for permission checks */
    /* This is necesarry because the requested_permission bitfield is
     * in another format (no notion of group/user/other) than the stat() return mode bit field */
    int requested_user_permissions_bitmask   = 0;
    int requested_group_permissions_bitmask  = 0;
    int requested_others_permissions_bitmask = 0;

    if (requested_permissions & R_OK) {
        requested_user_permissions_bitmask   |= S_IRUSR;
        requested_group_permissions_bitmask  |= S_IRGRP;
        requested_others_permissions_bitmask |= S_IROTH;
    }
    if (requested_permissions & W_OK) {
        requested_user_permissions_bitmask   |= S_IWUSR;
        requested_group_permissions_bitmask  |= S_IWGRP;
        requested_others_permissions_bitmask |= S_IWOTH;
    }
    if (requested_permissions & X_OK) {
        requested_user_permissions_bitmask   |= S_IXUSR;
        requested_group_permissions_bitmask  |= S_IXGRP;
        requested_others_permissions_bitmask |= S_IXOTH;
    }

    /* Step 2: Check the permission flags */

    /* if we are file owner... */
    if (asked_uid == file_stat_struct->st_uid) { /* check owner permissions */

        /* Here we check multiple flags at once by first querying all the
         * relevant bits with AND and than checking if all the relevant bits
         * are there. (They only are if the result is equal to the mask
         * i.e same bits set). Same happens for group and others */
        int const relevant_bits = file_stat_struct->st_mode
                                  & requested_user_permissions_bitmask;

        if (relevant_bits == requested_user_permissions_bitmask)
            return true;
    }

    /* for groups the process is in */
    for (int i = 0; i < gid_count; i++) {
        gid_t const gid_to_check = asked_gids[i];

        /* if it matches file group */
        if (gid_to_check == file_stat_struct->st_gid) {
            int const relevant_bits = file_stat_struct->st_mode
                                      & requested_group_permissions_bitmask;
            if (relevant_bits == requested_group_permissions_bitmask)
                return true;
         }
    }

    /* check "others" permissions */
    int const relevant_bits = file_stat_struct->st_mode
                              & requested_others_permissions_bitmask;
    if (relevant_bits == requested_others_permissions_bitmask) {
        return true;
    }

    return false;  /* none matched */
}

#endif /* OS_WIN32 */
