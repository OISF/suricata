/* Copyright (C) 2022,2026 Open Information Security Foundation
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
#include "detect-engine.h"
#include "feature.h"
#include "output.h"
#include "util-byte.h"
#include "util-conf.h"
#include "util-file.h"
#include "util-landlock.h"
#include "util-mem.h"
#include "util-path.h"
#include "util-plugin.h"
#include "util-validate.h"

/**
 * \brief Run \a cb for every enabled instance of the \a name output
 *
 * The "outputs" configuration is a YAML sequence, so an output is found at
 * outputs.<n>.<name> and can be declared more than once. Instances whose
 * "enabled" key is absent or not true are skipped.
 *
 * \param ruleset opaque landlock ruleset, passed as-is to \a cb
 * \param name name of the output, as used in the YAML configuration
 * \param cb callback run for each enabled instance of the output
 */
void SCLandlockForEachOutput(void *ruleset, const char *name, SCLandlockOutputFunc cb)
{
    if (name == NULL || cb == NULL)
        return;

    SCConfNode *outputs = SCConfGetNode("outputs");
    if (outputs == NULL)
        return;

    SCConfNode *conf = NULL;
    while ((conf = SCConfNodeLookupInSequence(outputs, name, conf)) != NULL) {
        const char *enabled = SCConfNodeLookupChildValue(conf, "enabled");
        if (enabled == NULL || !SCConfValIsTrue(enabled))
            continue;
        cb(ruleset, conf);
    }
}

#ifndef HAVE_LINUX_LANDLOCK_H

void LandlockSandboxing(SCInstance *suri)
{
}

void SCLandlockGrantReadPath(void *ruleset, const char *path)
{
}

void SCLandlockGrantWritePath(void *ruleset, const char *path)
{
}

void SCLandlockGrantNetBindTCP(void *ruleset, uint16_t port)
{
}

void SCLandlockGrantNetConnectTCP(void *ruleset, uint16_t port)
{
}

#else /* HAVE_LINUX_LANDLOCK_H */

#include <linux/landlock.h>

#ifndef landlock_create_ruleset
static inline int landlock_create_ruleset(
        const struct landlock_ruleset_attr *const attr, const size_t size, const __u32 flags)
{
    long r = syscall(__NR_landlock_create_ruleset, attr, size, flags);
    DEBUG_VALIDATE_BUG_ON(r > INT_MAX);
    return (int)r;
}
#endif

#ifndef landlock_add_rule
static inline int landlock_add_rule(const int ruleset_fd, const enum landlock_rule_type rule_type,
        const void *const rule_attr, const __u32 flags)
{
    long r = syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr, flags);
    DEBUG_VALIDATE_BUG_ON(r > INT_MAX);
    return (int)r;
}
#endif

#ifndef landlock_restrict_self
static inline int landlock_restrict_self(const int ruleset_fd, const __u32 flags)
{
    long r = syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
    DEBUG_VALIDATE_BUG_ON(r > INT_MAX);
    return (int)r;
}
#endif

#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif

#ifndef LANDLOCK_ACCESS_FS_RESOLVE_UNIX
#define LANDLOCK_ACCESS_FS_RESOLVE_UNIX (1ULL << 18)
#endif

#define _LANDLOCK_ACCESS_FS_WRITE                                                                  \
    (LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |                               \
            LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR |                        \
            LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |                            \
            LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |                          \
            LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM |                          \
            LANDLOCK_ACCESS_FS_REFER | LANDLOCK_ACCESS_FS_TRUNCATE |                               \
            LANDLOCK_ACCESS_FS_IOCTL_DEV | LANDLOCK_ACCESS_FS_RESOLVE_UNIX)

#define _LANDLOCK_ACCESS_FS_READ (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR)

#define _LANDLOCK_SURI_ACCESS_FS_WRITE                                                             \
    (LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |   \
            LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_SOCK)

#ifndef LANDLOCK_ACCESS_NET_BIND_TCP
#define LANDLOCK_ACCESS_NET_BIND_TCP (1ULL << 0)
#endif
#ifndef LANDLOCK_ACCESS_NET_CONNECT_TCP
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)
#endif
#define _LANDLOCK_ACCESS_NET (LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP)

struct landlock_ruleset {
    int fd;
    struct landlock_ruleset_attr attr;
};

static inline struct landlock_ruleset *LandlockCreateRuleset(void)
{
    struct landlock_ruleset *ruleset = SCCalloc(1, sizeof(struct landlock_ruleset));
    if (ruleset == NULL) {
        SCLogError("Can't alloc landlock ruleset");
        return NULL;
    }

    ruleset->attr.handled_access_fs =
            _LANDLOCK_ACCESS_FS_READ | _LANDLOCK_ACCESS_FS_WRITE | LANDLOCK_ACCESS_FS_EXECUTE;
    ruleset->attr.handled_access_net = _LANDLOCK_ACCESS_NET;

    int abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        SCFree(ruleset);
        return NULL;
    }
    switch (abi) {
        case 1:
            /* Refer is only available from ABI 2 */
            if (SCRequiresFeature(FEATURE_OUTPUT_FILESTORE)) {
                SCLogError("Landlock disabled: need Linux 5.19+ for file store support");
                SCFree(ruleset);
                return NULL;
            } else {
                ruleset->attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_REFER;
            }
            __attribute__((fallthrough));
        case 2:
            /* Truncate is only available from ABI 3 */
            ruleset->attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_TRUNCATE;
            __attribute__((fallthrough));
        case 3:
            /* Network access is only available from ABI 4 */
            ruleset->attr.handled_access_net &= ~_LANDLOCK_ACCESS_NET;
            __attribute__((fallthrough));
        case 4:
            /* Device ioctl is only available from ABI 5 */
            ruleset->attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_IOCTL_DEV;
            __attribute__((fallthrough));
        case 5:
            /* Scoping is only available from ABI 6 */
            ruleset->attr.scoped &= ~(LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL);
            __attribute__((fallthrough));
        case 6 ... 8:
            /* Unix socket resolution is only available from ABI 9 */
            ruleset->attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_RESOLVE_UNIX;
    }

    ruleset->fd = landlock_create_ruleset(&ruleset->attr, sizeof(ruleset->attr), 0);
    if (ruleset->fd < 0) {
        SCFree(ruleset);
        SCLogError("Can't create landlock ruleset");
        return NULL;
    }
    return ruleset;
}

static inline void LandlockEnforceRuleset(struct landlock_ruleset *ruleset)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        SCLogError("Can't self restrict (prctl phase): %s", strerror(errno));
        return;
    }
    if (landlock_restrict_self(ruleset->fd, 0)) {
        SCLogError("Can't self restrict (landlock phase): %s", strerror(errno));
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
        SCLogError("Can't open %s", directory);
        return -1;
    }
    path_beneath.parent_fd = dir_fd;

    if (landlock_add_rule(ruleset->fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0)) {
        SCLogError("Can't add write rule: %s", strerror(errno));
        close(dir_fd);
        return -1;
    }

    close(dir_fd);
    return 0;
}

void SCLandlockGrantWritePath(void *vruleset, const char *directory)
{
    struct landlock_ruleset *ruleset = vruleset;
    if (ruleset == NULL || directory == NULL)
        return;
    if (LandlockSandboxingAddRule(ruleset, directory, _LANDLOCK_SURI_ACCESS_FS_WRITE) == 0) {
        SCLogConfig("Added write permission to '%s'", directory);
    }
}

void SCLandlockGrantReadPath(void *vruleset, const char *directory)
{
    struct landlock_ruleset *ruleset = vruleset;
    if (ruleset == NULL || directory == NULL)
        return;
    if (LandlockSandboxingAddRule(ruleset, directory, _LANDLOCK_ACCESS_FS_READ) == 0) {
        SCLogConfig("Added read permission to '%s'", directory);
    }
}

static void LandlockGrantNetPort(
        struct landlock_ruleset *ruleset, uint16_t port, uint64_t access, const char *access_name)
{
    if (ruleset == NULL)
        return;
    if ((ruleset->attr.handled_access_net & access) == 0) {
        SCLogInfo("Landlock network access %s not available; skipping port %u", access_name, port);
        return;
    }
    struct landlock_net_port_attr net_port = {
        .allowed_access = access,
        .port = port,
    };
    if (landlock_add_rule(ruleset->fd, LANDLOCK_RULE_NET_PORT, &net_port, 0)) {
        SCLogError("Can't add net rule (%s, port %u): %s", access_name, port, strerror(errno));
        return;
    }
    SCLogConfig("Added net %s permission on port %u", access_name, port);
}

/**
 * \brief Grant TCP bind permission on the given port
 *
 * Silently no-op when running on a kernel where landlock network support is
 * not available.
 *
 * \param vruleset opaque landlock ruleset
 * \param port TCP port to allow bind() on
 */
void SCLandlockGrantNetBindTCP(void *vruleset, uint16_t port)
{
#ifdef LANDLOCK_ACCESS_NET_BIND_TCP
    LandlockGrantNetPort(
            (struct landlock_ruleset *)vruleset, port, LANDLOCK_ACCESS_NET_BIND_TCP, "bind-tcp");
#else
    (void)vruleset;
    (void)port;
#endif
}

/**
 * \brief Grant TCP connect permission on the given port
 *
 * Silently no-op when running on a kernel where landlock network support is
 * not available.
 *
 * \param vruleset opaque landlock ruleset
 * \param port TCP port to allow connect() on
 */
void SCLandlockGrantNetConnectTCP(void *vruleset, uint16_t port)
{
#ifdef LANDLOCK_ACCESS_NET_CONNECT_TCP
    LandlockGrantNetPort((struct landlock_ruleset *)vruleset, port, LANDLOCK_ACCESS_NET_CONNECT_TCP,
            "connect-tcp");
#else
    (void)vruleset;
    (void)port;
#endif
}

static void LandlockSandboxingApplyNetPorts(
        void *v_ruleset, const char *conf_key, void (*grant)(void *, uint16_t))
{
    struct landlock_ruleset *ruleset = v_ruleset;
    SCConfNode *ports = SCConfGetNode(conf_key);
    if (ports == NULL)
        return;
    if (!SCConfNodeIsSequence(ports)) {
        SCLogWarning(
                "Invalid %s configuration section: expected a list of port numbers.", conf_key);
        return;
    }
    SCConfNode *port_node;
    TAILQ_FOREACH (port_node, &ports->head, next) {
        if (port_node->val == NULL)
            continue;
        uint16_t port = 0;
        if (StringParseUint16(&port, 10, 0, port_node->val) < 0 || port == 0) {
            SCLogWarning("Invalid port '%s' in %s: expected a value in [1, 65535].", port_node->val,
                    conf_key);
            continue;
        }
        grant(ruleset, port);
    }
}

/** \brief Grant read access on the system pseudo-filesystem paths in use.
 *
 *  These are the paths glibc, jemalloc and the Rust standard library read
 *  during startup and runtime. A path that does not exist is skipped.
 *
 *  \param ruleset the landlock ruleset to add the read rules to
 */
static void LandlockGrantSystemReadPaths(struct landlock_ruleset *ruleset)
{
    static const char *const system_read_paths[] = {
        "/sys/devices/system/cpu",        /* sysconf(_SC_NPROCESSORS_*) */
        "/proc/stat",                     /* CPU/system statistics */
        "/proc/sys/vm/overcommit_memory", /* malloc tuning */
        "/dev/urandom",                   /* RNG seeding fallback */
    };

    for (size_t i = 0; i < sizeof(system_read_paths) / sizeof(system_read_paths[0]); i++) {
        const char *path = system_read_paths[i];
        /* Open directly instead of stat()+open() to avoid a TOCTOU race: a
         * missing or unreadable path simply fails here and is skipped. */
        int path_fd = open(path, O_PATH | O_CLOEXEC);
        if (path_fd == -1) {
            SCLogDebug("Can't open %s for landlock: %s", path, strerror(errno));
            continue;
        }
        struct landlock_path_beneath_attr path_beneath = {
            .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE & ruleset->attr.handled_access_fs,
            .parent_fd = path_fd,
        };
        if (landlock_add_rule(ruleset->fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0)) {
            SCLogDebug("Can't add system read rule for %s: %s", path, strerror(errno));
        }
        close(path_fd);
    }
}

void LandlockSandboxing(SCInstance *suri)
{
    /* Read configuration variable and exit if no enforcement */
    int conf_status;
    if (SCConfGetBool("security.landlock.enabled", &conf_status) == 0) {
        conf_status = 0;
    }
    if (!conf_status) {
        SCLogConfig("Landlock is not enabled in configuration");
        return;
    }
    struct landlock_ruleset *ruleset = LandlockCreateRuleset();
    if (ruleset == NULL) {
        SCLogError("Kernel does not support Landlock");
        return;
    }

    LandlockGrantSystemReadPaths(ruleset);

    SCLandlockGrantWritePath(ruleset, SCConfigGetLogDirectory());
    struct stat sb;
    if (stat(ConfigGetDataDirectory(), &sb) == 0) {
        LandlockSandboxingAddRule(ruleset, ConfigGetDataDirectory(),
                _LANDLOCK_SURI_ACCESS_FS_WRITE | _LANDLOCK_ACCESS_FS_READ);
    }
    if (DetectEngineMpmCachingEnabled() && stat(DetectEngineMpmCachingGetPath(), &sb) == 0) {
        LandlockSandboxingAddRule(ruleset, DetectEngineMpmCachingGetPath(),
                _LANDLOCK_SURI_ACCESS_FS_WRITE | _LANDLOCK_ACCESS_FS_READ);
    }
    if (suri->run_mode == RUNMODE_PCAP_FILE) {
        const char *pcap_file;
        if (SCConfGetNonNull("pcap-file.file", &pcap_file) == 1) {
            char *file_name = SCStrdup(pcap_file);
            if (file_name != NULL) {
                struct stat statbuf;
                if (stat(file_name, &statbuf) != -1) {
                    if (S_ISDIR(statbuf.st_mode)) {
                        SCLandlockGrantReadPath(ruleset, file_name);
                    } else {
                        SCLandlockGrantReadPath(ruleset, dirname(file_name));
                    }
                } else {
                    SCLogError("Can't open pcap file");
                }
                SCFree(file_name);
            }
        }
    }
    if (suri->sig_file) {
        char *file_name = SCStrdup(suri->sig_file);
        if (file_name != NULL) {
            SCLandlockGrantReadPath(ruleset, dirname(file_name));
            SCFree(file_name);
        }
    }
    if (suri->pid_filename) {
        char *file_name = SCStrdup(suri->pid_filename);
        if (file_name != NULL) {
            SCLandlockGrantWritePath(ruleset, dirname(file_name));
            SCFree(file_name);
        }
    }
    if (ConfUnixSocketIsEnable()) {
        const char *socketname;
        if (SCConfGetNonNull("unix-command.filename", &socketname) == 1) {
            if (PathIsAbsolute(socketname)) {
                char *file_name = SCStrdup(socketname);
                if (file_name != NULL) {
                    SCLandlockGrantWritePath(ruleset, dirname(file_name));
                    SCFree(file_name);
                }
            } else {
                SCLandlockGrantWritePath(ruleset, LOCAL_STATE_DIR "/run/suricata/");
            }
        } else {
            SCLandlockGrantWritePath(ruleset, LOCAL_STATE_DIR "/run/suricata/");
        }
    }
    if (!suri->sig_file_exclusive) {
        const char *rule_path;
        if (SCConfGetNonNull("default-rule-path", &rule_path) == 1 && rule_path) {
            SCLandlockGrantReadPath(ruleset, rule_path);
        }
    }

    SCConfNode *read_dirs = SCConfGetNode("security.landlock.directories.read");
    if (read_dirs) {
        if (!SCConfNodeIsSequence(read_dirs)) {
            SCLogWarning("Invalid security.landlock.directories.read configuration section: "
                         "expected a list of directory names.");
        } else {
            SCConfNode *directory;
            TAILQ_FOREACH (directory, &read_dirs->head, next) {
                SCLandlockGrantReadPath(ruleset, directory->val);
            }
        }
    }
    SCConfNode *write_dirs = SCConfGetNode("security.landlock.directories.write");
    if (write_dirs) {
        if (!SCConfNodeIsSequence(write_dirs)) {
            SCLogWarning("Invalid security.landlock.directories.write configuration section: "
                         "expected a list of directory names.");
        } else {
            SCConfNode *directory;
            TAILQ_FOREACH (directory, &write_dirs->head, next) {
                SCLandlockGrantWritePath(ruleset, directory->val);
            }
        }
    }

    LandlockSandboxingApplyNetPorts(
            ruleset, "security.landlock.network.connect.tcp", SCLandlockGrantNetConnectTCP);
    LandlockSandboxingApplyNetPorts(
            ruleset, "security.landlock.network.bind.tcp", SCLandlockGrantNetBindTCP);

    /* Let plugins declare their landlock needs. */
#ifdef HAVE_PLUGINS
    SCPluginsLandlockEnable(ruleset);
#endif

    /* Let registered output modules declare theirs. */
    OutputModule *output_module;
    TAILQ_FOREACH (output_module, &output_modules, entries) {
        if (output_module->LandlockEnable != NULL) {
            output_module->LandlockEnable(ruleset);
        }
    }

    LandlockEnforceRuleset(ruleset);
    SCFree(ruleset);
}

#endif /* HAVE_LINUX_LANDLOCK_H */
