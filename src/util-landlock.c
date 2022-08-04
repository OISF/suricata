/* Copyright (C) 2022 Open Information Security Foundation
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
 * \author Eric Leblond <el@stamus-networks.com>
 */

#include "suricata.h"
#include "util-conf.h"
#include "util-file.h"
#include "util-landlock.h"
#include "util-mem.h"

#ifndef HAVE_LINUX_LANDLOCK_H

void LandlockSandboxing(SCInstance *suri)
{
    return;
}

#else /* HAVE_LINUX_LANDLOCK_H */

#include <linux/landlock.h>

#ifndef landlock_create_ruleset
static inline int landlock_create_ruleset(
        const struct landlock_ruleset_attr *const attr, const size_t size, const __u32 flags)
{
    return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef landlock_add_rule
static inline int landlock_add_rule(const int ruleset_fd, const enum landlock_rule_type rule_type,
        const void *const rule_attr, const __u32 flags)
{
    return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr, flags);
}
#endif

#ifndef landlock_restrict_self
static inline int landlock_restrict_self(const int ruleset_fd, const __u32 flags)
{
    return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif

#define _LANDLOCK_ACCESS_FS_WRITE                                                                  \
    (LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |                               \
            LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR |                        \
            LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |                            \
            LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |                          \
            LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM |                          \
            LANDLOCK_ACCESS_FS_REFER)

#define _LANDLOCK_ACCESS_FS_READ (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR)

#define _LANDLOCK_SURI_ACCESS_FS_WRITE                                                             \
    (LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |   \
            LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_SOCK)

struct landlock_ruleset {
    int fd;
    struct landlock_ruleset_attr attr;
};

static inline struct landlock_ruleset* LandlockCreateRuleset()
{
    struct landlock_ruleset *ruleset = SCMalloc(sizeof(struct landlock_ruleset));

    if (ruleset == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Can't alloc landlock ruleset");
        return NULL;
    }

    ruleset->attr.handled_access_fs =
                _LANDLOCK_ACCESS_FS_READ | _LANDLOCK_ACCESS_FS_WRITE | LANDLOCK_ACCESS_FS_EXECUTE;

    int abi;
    abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        SCFree(ruleset);
        return NULL;
    }
    if (abi < 2) {
        if (FileStoreIsEnabled()) {
            SCLogError(SC_ERR_NOT_SUPPORTED, "Landlock disabled: need Linux 5.19+ for file store support");
            SCFree(ruleset);
            return NULL;
        } else {
            ruleset->attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_REFER;
        }
    }

    ruleset->fd = landlock_create_ruleset(&ruleset->attr, sizeof(ruleset->attr), 0);
    if (ruleset->fd < 0) {
        SCFree(ruleset);
        ruleset = NULL;
        SCLogError(SC_ERR_CONF_YAML_ERROR, "Can't create landlock ruleset");
    }
    return ruleset;
}

static inline void LandlockEnforceRuleset(struct landlock_ruleset *ruleset)
{
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (landlock_restrict_self(ruleset->fd, 0))
        SCLogError(SC_ERR_CONF_YAML_ERROR, "Can't self restrict: %s", strerror(errno));
}

static int LandlockSandboxingAddRule(struct landlock_ruleset *ruleset, const char *directory, uint64_t permission)
{
    struct landlock_path_beneath_attr path_beneath = {
        .allowed_access = permission & ruleset->attr.handled_access_fs,
    };

    int dir_fd = open(directory, O_PATH | O_CLOEXEC | O_DIRECTORY);
    if (dir_fd != -1)
        path_beneath.parent_fd = dir_fd;
    else {
        SCLogError(SC_ERR_CONF_YAML_ERROR, "Can't open %s", directory);
        return -1;
    }

    if (landlock_add_rule(ruleset->fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0)) {
        SCLogError(SC_ERR_CONF_YAML_ERROR, "Can't add write rule: %s", strerror(errno));
        close(dir_fd);
        return -1;
    }

    if (dir_fd == -1)
        close(dir_fd);

    return 0;
}

static inline void LandlockSandboxingWritePath(struct landlock_ruleset *ruleset, const char *directory)
{
    if (LandlockSandboxingAddRule(ruleset, directory, _LANDLOCK_SURI_ACCESS_FS_WRITE) == 0) {
        SCLogInfo("Added write permission to '%s'", directory);
    }
}

static inline void LandlockSandboxingReadPath(struct landlock_ruleset *ruleset, const char *directory)
{
    if (LandlockSandboxingAddRule(ruleset, directory, _LANDLOCK_ACCESS_FS_READ) == 0) {
        SCLogInfo("Added read permission to '%s'", directory);
    }
}

void LandlockSandboxing(SCInstance *suri)
{
    /* Read configuration variable and exit if no enforcement */
    int conf_status;
    ConfGetBool("landlock.enabled", &conf_status);
    if (!conf_status) {
        SCLogNotice("Landlock is not enabled in configuration");
        return;
    }
    struct landlock_ruleset *ruleset = LandlockCreateRuleset();
    if (ruleset == NULL) {
        SCLogError(SC_ERR_NOT_SUPPORTED, "Kernel does not support Landlock");
        return;
    }

    LandlockSandboxingWritePath(ruleset, ConfigGetLogDirectory());
    struct stat sb;
    if (stat(ConfigGetDataDirectory(), &sb) == 0) {
        LandlockSandboxingAddRule(ruleset, ConfigGetDataDirectory(),
                _LANDLOCK_SURI_ACCESS_FS_WRITE | _LANDLOCK_ACCESS_FS_READ);
    }
    if (suri->run_mode == RUNMODE_PCAP_FILE) {
        const char *pcap_file;
        ConfGet("pcap-file.file", &pcap_file);
        char *base_dir = SCStrdup(pcap_file);
        if (base_dir != NULL) {
            LandlockSandboxingReadPath(ruleset, dirname(base_dir));
            SCFree(base_dir);
        }
    }
    if (suri->sig_file) {
        char *base_dir = SCStrdup(suri->sig_file);
        if (base_dir != NULL) {
            LandlockSandboxingReadPath(ruleset, dirname(base_dir));
            SCFree(base_dir);
        }
    }
    if (suri->pid_filename) {
        char *base_dir = SCStrdup(suri->pid_filename);
        if (base_dir != NULL) {
            LandlockSandboxingWritePath(ruleset, dirname(base_dir));
            SCFree(base_dir);
        }
    }
    if (ConfUnixSocketIsEnable()) {
        const char *socketname;
        if (ConfGet("unix-command.filename", &socketname) == 1) {
            if (PathIsAbsolute(socketname)) {
                char *base_dir = SCStrdup(socketname);
                if (base_dir != NULL) {
                    LandlockSandboxingWritePath(ruleset, dirname(base_dir));
                    SCFree(base_dir);
                }
            } else {
                LandlockSandboxingWritePath(ruleset, LOCAL_STATE_DIR "/run/suricata/");
            }
        } else {
            LandlockSandboxingWritePath(ruleset, LOCAL_STATE_DIR "/run/suricata/");
        }
    }
    if (!suri->sig_file_exclusive) {
        const char *rule_path;
        ConfGet("default-rule-path", &rule_path);
        if (rule_path) {
            LandlockSandboxingReadPath(ruleset, rule_path);
        }
    }

    ConfNode *read_dirs = ConfGetNode("landlock.directories.read");
    if (read_dirs) {
        if (!ConfNodeIsSequence(read_dirs)) {
            SCLogWarning(SC_ERR_INVALID_ARGUMENT,
                    "Invalid landlock.directories.read configuration section: "
                    "expected a list of directory names.");
        } else {
            ConfNode *directory;
            TAILQ_FOREACH (directory, &read_dirs->head, next) {
                LandlockSandboxingReadPath(ruleset, directory->val);
            }
        }
    }
    ConfNode *write_dirs = ConfGetNode("landlock.directories.write");
    if (write_dirs) {
        if (!ConfNodeIsSequence(write_dirs)) {
            SCLogWarning(SC_ERR_INVALID_ARGUMENT,
                    "Invalid landlock.directories.write configuration section: "
                    "expected a list of directory names.");
        } else {
            ConfNode *directory;
            TAILQ_FOREACH (directory, &write_dirs->head, next) {
                LandlockSandboxingWritePath(ruleset, directory->val);
            }
        }
    }
    LandlockEnforceRuleset(ruleset);
    SCFree(ruleset);
}

#endif /* HAVE_LINUX_LANDLOCK_H */
