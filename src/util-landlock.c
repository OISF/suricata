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
#include "feature.h"
#include "util-conf.h"
#include "util-file.h"
#include "util-landlock.h"
#include "util-mem.h"
#include "util-path.h"

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
            LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_SOCK |                        \
            LANDLOCK_ACCESS_FS_REFER)

struct landlock_ruleset {
    int fd;
    struct landlock_ruleset_attr attr;
};

static inline struct landlock_ruleset *LandlockCreateRuleset(void)
{
    struct landlock_ruleset *ruleset = SCCalloc(1, sizeof(struct landlock_ruleset));
    if (ruleset == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Can't alloc landlock ruleset");
        return NULL;
    }

    ruleset->attr.handled_access_fs =
            _LANDLOCK_ACCESS_FS_READ | _LANDLOCK_ACCESS_FS_WRITE | LANDLOCK_ACCESS_FS_EXECUTE;

    int abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        SCFree(ruleset);
        return NULL;
    }
    if (abi < 2) {
        if (RequiresFeature(FEATURE_OUTPUT_FILESTORE)) {
            SCLogError(SC_ERR_NOT_SUPPORTED,
                    "Landlock disabled: need Linux 5.19+ for file store support");
            SCFree(ruleset);
            return NULL;
        } else {
            ruleset->attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_REFER;
        }
    }

    ruleset->fd = landlock_create_ruleset(&ruleset->attr, sizeof(ruleset->attr), 0);
    if (ruleset->fd < 0) {
        SCFree(ruleset);
        SCLogError(SC_ERR_CONF_YAML_ERROR, "Can't create landlock ruleset");
        return NULL;
    }
    return ruleset;
}

static inline void LandlockEnforceRuleset(struct landlock_ruleset *ruleset)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        SCLogError(
                SC_ERR_CONF_YAML_ERROR, "Can't self restrict (prctl phase): %s", strerror(errno));
        return;
    }
    if (landlock_restrict_self(ruleset->fd, 0)) {
        SCLogError(SC_ERR_CONF_YAML_ERROR, "Can't self restrict (landlock phase): %s",
                strerror(errno));
    }
}

static int LandlockSandboxingAddRule(
        struct landlock_ruleset *ruleset, const char *directory, uint64_t permission)
{
    struct landlock_path_beneath_attr path_beneath = {
        .allowed_access = permission & ruleset->attr.handled_access_fs,
    };

    int dir_fd = open(directory, O_PATH | O_CLOEXEC | O_DIRECTORY);
    if (dir_fd == -1) {
        SCLogError(SC_ERR_CONF_YAML_ERROR, "Can't open %s", directory);
        return -1;
    }
    path_beneath.parent_fd = dir_fd;

    if (landlock_add_rule(ruleset->fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0)) {
        SCLogError(SC_ERR_CONF_YAML_ERROR, "Can't add write rule: %s", strerror(errno));
        close(dir_fd);
        return -1;
    }

    close(dir_fd);
    return 0;
}

static inline void LandlockSandboxingWritePath(
        struct landlock_ruleset *ruleset, const char *directory)
{
    if (LandlockSandboxingAddRule(ruleset, directory, _LANDLOCK_SURI_ACCESS_FS_WRITE) == 0) {
        SCLogConfig("Added write permission to '%s'", directory);
    }
}

static inline void LandlockSandboxingReadPath(
        struct landlock_ruleset *ruleset, const char *directory)
{
    if (LandlockSandboxingAddRule(ruleset, directory, _LANDLOCK_ACCESS_FS_READ) == 0) {
        SCLogConfig("Added read permission to '%s'", directory);
    }
}

void LandlockSandboxing(SCInstance *suri)
{
    /* Read configuration variable and exit if no enforcement */
    int conf_status;
    ConfGetBool("security.landlock.enabled", &conf_status);
    if (!conf_status) {
        SCLogConfig("Landlock is not enabled in configuration");
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
        char *file_name = SCStrdup(pcap_file);
        if (file_name != NULL) {
            struct stat statbuf;
            if (stat(file_name, &statbuf) != -1) {
                if (S_ISDIR(statbuf.st_mode)) {
                    LandlockSandboxingReadPath(ruleset, file_name);
                } else {
                    LandlockSandboxingReadPath(ruleset, dirname(file_name));
                }
            } else {
                SCLogError(SC_ERR_OPENING_FILE, "Can't open pcap file");
            }
            SCFree(file_name);
        }
    }
    if (suri->sig_file) {
        char *file_name = SCStrdup(suri->sig_file);
        if (file_name != NULL) {
            LandlockSandboxingReadPath(ruleset, dirname(file_name));
            SCFree(file_name);
        }
    }
    if (suri->pid_filename) {
        char *file_name = SCStrdup(suri->pid_filename);
        if (file_name != NULL) {
            LandlockSandboxingWritePath(ruleset, dirname(file_name));
            SCFree(file_name);
        }
    }
    if (ConfUnixSocketIsEnable()) {
        const char *socketname;
        if (ConfGet("unix-command.filename", &socketname) == 1) {
            if (PathIsAbsolute(socketname)) {
                char *file_name = SCStrdup(socketname);
                if (file_name != NULL) {
                    LandlockSandboxingWritePath(ruleset, dirname(file_name));
                    SCFree(file_name);
                }
            } else {
                LandlockSandboxingWritePath(ruleset, LOCAL_STATE_DIR "/run/suricata/");
            }
        } else {
            LandlockSandboxingWritePath(ruleset, LOCAL_STATE_DIR "/run/suricata/");
        }
    }
    if (suri->sig_file_exclusive == FALSE) {
        const char *rule_path;
        ConfGet("default-rule-path", &rule_path);
        if (rule_path) {
            LandlockSandboxingReadPath(ruleset, rule_path);
        }
    }

    ConfNode *read_dirs = ConfGetNode("security.landlock.directories.read");
    if (read_dirs) {
        if (!ConfNodeIsSequence(read_dirs)) {
            SCLogWarning(SC_ERR_INVALID_ARGUMENT,
                    "Invalid security.landlock.directories.read configuration section: "
                    "expected a list of directory names.");
        } else {
            ConfNode *directory;
            TAILQ_FOREACH (directory, &read_dirs->head, next) {
                LandlockSandboxingReadPath(ruleset, directory->val);
            }
        }
    }
    ConfNode *write_dirs = ConfGetNode("security.landlock.directories.write");
    if (write_dirs) {
        if (!ConfNodeIsSequence(write_dirs)) {
            SCLogWarning(SC_ERR_INVALID_ARGUMENT,
                    "Invalid security.landlock.directories.write configuration section: "
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
