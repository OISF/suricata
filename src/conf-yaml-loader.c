/* Copyright (C) 2007-2026 Open Information Security Foundation
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
 * \author Endace Technology Limited - Jason Ish <jason.ish@endace.com>
 *
 * YAML configuration loader backed by the Rust config parser.
 */

#include "suricata-common.h"
#include "conf.h"
#include "conf-yaml-loader.h"
#include "rust-config.h"
#include "util-path.h"
#include "util-debug.h"
#include "util-unittest.h"

#define MANGLE_ERRORS_MAX 10

static int mangle_errors = 0;
static char *conf_dirname = NULL;

/**
 * \brief Mangle unsupported characters.
 *
 * \param string A pointer to an null terminated string.
 *
 * \retval none
 */
static void
Mangle(char *string)
{
    char *c;

    while ((c = strchr(string, '_')))
        *c = '-';
}

/**
 * \brief Set the directory name of the configuration file.
 *
 * \param filename The configuration filename.
 */
static void ConfYamlSetConfDirname(const char *filename)
{
    const char *ep;

    ep = strrchr(filename, '\\');
    if (ep == NULL) {
        ep = strrchr(filename, '/');
    }

    if (ep == NULL) {
        conf_dirname = SCStrdup(".");
        if (conf_dirname == NULL) {
            FatalError("ERROR: Failed to allocate memory while loading configuration.");
        }
        return;
    }

    conf_dirname = SCStrdup(filename);
    if (conf_dirname == NULL) {
        FatalError("ERROR: Failed to allocate memory while loading configuration.");
    }
    conf_dirname[ep - filename] = '\0';
}

/**
 * \brief Resolve a filename against conf_dirname when needed.
 *
 * \retval 0 on success, -1 on failure.
 */
static int ConfYamlResolveFilename(const char *filename, char *resolved, size_t resolved_len)
{
    if (PathIsAbsolute(filename) || conf_dirname == NULL) {
        if (strlcpy(resolved, filename, resolved_len) >= resolved_len) {
            return -1;
        }
        return 0;
    }

    int ret = snprintf(resolved, resolved_len, "%s/%s", conf_dirname, filename);
    if (ret < 0 || (size_t)ret >= resolved_len) {
        return -1;
    }

    return 0;
}

/**
 * \brief Log the latest Rust config loader error.
 */
static void ConfYamlLogRustError(const char *context, const char *target)
{
    const char *error = SCConfigGetLastError();
    if (error != NULL) {
        if (target != NULL) {
            SCLogError("%s %s: %s", context, target, error);
        } else {
            SCLogError("%s: %s", context, error);
        }
        return;
    }

    if (target != NULL) {
        SCLogError("%s %s", context, target);
    } else {
        SCLogError("%s", context);
    }
}

/**
 * \brief Check if a node name is all digits.
 */
static bool ConfYamlNodeNameIsIndex(const char *name)
{
    if (name == NULL || *name == '\0') {
        return false;
    }

    for (const char *c = name; *c != '\0'; c++) {
        if (!isdigit((unsigned char)*c)) {
            return false;
        }
    }

    return true;
}

/**
 * \brief Return true if a parent node allows underscores in child names.
 */
static bool ConfYamlAllowUnderscores(const SCConfNode *parent)
{
    if (parent == NULL || parent->name == NULL) {
        return false;
    }

    return strcmp(parent->name, "address-groups") == 0 || strcmp(parent->name, "port-groups") == 0;
}

/**
 * \brief Copy and normalize a node name.
 */
static char *ConfYamlNormalizeNodeName(const SCConfNode *parent, const char *name)
{
    char *normalized = SCStrdup(name);
    if (unlikely(normalized == NULL)) {
        return NULL;
    }

    if (strchr(normalized, '_') != NULL && !ConfYamlAllowUnderscores(parent)) {
        Mangle(normalized);
        if (mangle_errors < MANGLE_ERRORS_MAX) {
            SCLogWarning("%s is deprecated. Please use %s.", name, normalized);
            mangle_errors++;
            if (mangle_errors >= MANGLE_ERRORS_MAX) {
                SCLogWarning("not showing more parameter name warnings.");
            }
        }
    }

    return normalized;
}

/**
 * \brief Set node value from Rust data.
 *
 * \param mangle_seq_key if true and value contains '_', mangle it like
 *        sequence mapping keys from the legacy parser.
 *
 * \retval 0 on success, -1 on allocation failure.
 */
static int ConfYamlSetNodeValue(SCConfNode *node, const char *value, bool mangle_seq_key)
{
    char *new_value = NULL;
    char *tmp = NULL;

    /*
     * Final nodes normally keep their value, but sequence placeholder nodes
     * created by --set need one-time backfill of their mapping key name.
     * This mirrors the legacy YAML parser behavior.
     */
    bool set_node_value = !node->final || (mangle_seq_key && node->val == NULL && value != NULL);

    if (set_node_value && value != NULL) {
        const char *src = value;
        if (mangle_seq_key && strchr(value, '_') != NULL) {
            tmp = SCStrdup(value);
            if (unlikely(tmp == NULL)) {
                return -1;
            }
            Mangle(tmp);
            src = tmp;
        }

        new_value = SCStrdup(src);
        if (unlikely(new_value == NULL)) {
            SCFree(tmp);
            return -1;
        }
    }

    if (set_node_value) {
        if (node->val != NULL) {
            SCFree(node->val);
        }
        node->val = new_value;
    } else if (new_value != NULL) {
        SCFree(new_value);
    }

    if (tmp != NULL) {
        SCFree(tmp);
    }

    return 0;
}

/**
 * \brief Return an existing node or create a new one for a child name.
 *
 * \param merge if true, merge into an existing node like for a dotted key,
 *        otherwise prune an existing node to replace it.
 */
static SCConfNode *ConfYamlGetNodeForName(SCConfNode *parent, const char *name, bool merge)
{
    if (strchr(name, '.') != NULL) {
        return SCConfNodeGetNodeOrCreate(parent, name, 0);
    }

    char *normalized_name = ConfYamlNormalizeNodeName(parent, name);
    if (unlikely(normalized_name == NULL)) {
        return NULL;
    }

    SCConfNode *node = SCConfNodeLookupChild(parent, normalized_name);
    if (node != NULL) {
        if (!merge) {
            if (!node->final) {
                SCLogInfo("Configuration node '%s' redefined.", node->name);
                SCConfNodePrune(node);
            }

            if (parent->is_seq && ConfYamlNodeNameIsIndex(normalized_name)) {
                TAILQ_REMOVE(&parent->head, node, next);
                TAILQ_INSERT_TAIL(&parent->head, node, next);
            }
        }

        SCFree(normalized_name);
        return node;
    }

    node = SCConfNodeNew();
    if (unlikely(node == NULL)) {
        SCFree(normalized_name);
        return NULL;
    }

    node->name = normalized_name;
    node->parent = parent;
    TAILQ_INSERT_TAIL(&parent->head, node, next);

    return node;
}

/**
 * \brief Merge a Rust config node into an SCConf subtree.
 *
 * \retval 0 on success, -1 on failure.
 */
static int ConfYamlMergeRustNode(SCConfNode *parent, const SCConfigNode *source)
{
    const char *name = SCConfigNodeName(source);
    if (name == NULL || name[0] == '\0') {
        SCLogError("Invalid node name in Rust configuration tree");
        return -1;
    }

    /* A mapping that only exists through dotted keys, like "vars" for
     * "vars.address-groups.HOME_NET", is merged into an existing node,
     * which keeps its value and type, like the legacy parser did. This
     * matters when merging into an already loaded configuration, like
     * with --include. */
    const bool merge = SCConfigNodeIsMerge(source);
    SCConfNode *node = ConfYamlGetNodeForName(parent, name, merge);
    if (unlikely(node == NULL)) {
        SCLogError("Failed to create configuration node for '%s'", name);
        return -1;
    }

    const size_t child_count = SCConfigNodeChildrenCount(source);
    if (!merge) {
        node->is_seq = SCConfigNodeIsSequence(source) ? 1 : 0;

        const bool mangle_seq_key =
                node->is_seq && child_count > 0 && ConfYamlNodeNameIsIndex(node->name);
        if (ConfYamlSetNodeValue(node, SCConfigNodeValue(source), mangle_seq_key) != 0) {
            SCLogError("Failed to set configuration node value for '%s'", node->name);
            return -1;
        }
    }

    for (size_t i = 0; i < child_count; i++) {
        const SCConfigNode *child = SCConfigNodeChildAt(source, i);
        if (child == NULL) {
            SCLogError("Failed to access child node %zu of '%s'", i, node->name);
            return -1;
        }

        if (ConfYamlMergeRustNode(node, child) != 0) {
            return -1;
        }
    }

    return 0;
}

/**
 * \brief Merge a loaded Rust config tree into an SCConf subtree.
 */
static int ConfYamlMergeRustConfig(SCConfNode *parent, const SCConfig *config)
{
    const SCConfigNode *root = SCConfigGetRoot(config);
    if (root == NULL) {
        SCLogError("Rust config loader returned an empty root node");
        return -1;
    }

    if (SCConfigNodeIsSequence(root)) {
        parent->is_seq = 1;
    }

    const size_t child_count = SCConfigNodeChildrenCount(root);
    for (size_t i = 0; i < child_count; i++) {
        const SCConfigNode *child = SCConfigNodeChildAt(root, i);
        if (child == NULL) {
            SCLogError("Failed to access root child node %zu", i);
            return -1;
        }

        if (ConfYamlMergeRustNode(parent, child) != 0) {
            return -1;
        }
    }

    return 0;
}

/**
 * \brief Load one file through Rust and merge it into parent.
 *
 * Relative includes, also those in included files, are resolved from
 * conf_dirname, the directory of the top-level configuration file.
 */
static int ConfYamlLoadRustFileIntoParent(SCConfNode *parent, const char *filename)
{
    SCConfig *config = SCConfigLoadFile(filename, conf_dirname);
    if (config == NULL) {
        ConfYamlLogRustError("Failed to load configuration file", filename);
        return -1;
    }

    int ret = ConfYamlMergeRustConfig(parent, config);
    SCConfigFree(config);

    return ret;
}

/**
 * \brief Load one YAML string through Rust and merge it into parent.
 */
static int ConfYamlLoadRustStringIntoParent(SCConfNode *parent, const char *string, size_t len)
{
    SCConfig *config = SCConfigLoadString((const uint8_t *)string, len);
    if (config == NULL) {
        ConfYamlLogRustError("Failed to load configuration string", NULL);
        return -1;
    }

    int ret = ConfYamlMergeRustConfig(parent, config);
    SCConfigFree(config);

    return ret;
}

/**
 * \brief Include a file in the configuration.
 *
 * \param parent The configuration node the included configuration will be
 *          placed at.
 * \param filename The filename to include.
 *
 * \retval 0 on success, -1 on failure.
 */
int SCConfYamlHandleInclude(SCConfNode *parent, const char *filename)
{
    char include_filename[PATH_MAX];

    if (unlikely(parent == NULL || filename == NULL)) {
        SCLogError("invalid include arguments");
        return -1;
    }

    if (ConfYamlResolveFilename(filename, include_filename, sizeof(include_filename)) != 0) {
        SCLogError("Failed to resolve include filename: %s", filename);
        return -1;
    }

    SCLogInfo("Including configuration file %s.", include_filename);
    return ConfYamlLoadRustFileIntoParent(parent, include_filename);
}

/**
 * \brief Load configuration from a YAML file.
 *
 * This function will load a configuration file.  On failure -1 will
 * be returned and it is suggested that the program then exit.  Any
 * errors while loading the configuration file will have already been
 * logged.
 *
 * \param filename Filename of configuration file to load.
 *
 * \retval 0 on success, -1 on failure.
 */
int SCConfYamlLoadFile(const char *filename)
{
    SCConfNode *root = SCConfGetRootNode();
    if (unlikely(root == NULL || filename == NULL)) {
        return -1;
    }

    struct stat stat_buf;
    if (stat(filename, &stat_buf) == 0) {
        if (stat_buf.st_mode & S_IFDIR) {
            SCLogError("yaml argument is not a file but a directory: %s. "
                       "Please specify the yaml file in your -c option.",
                    filename);
            return -1;
        }
    }

    if (conf_dirname == NULL) {
        ConfYamlSetConfDirname(filename);
    }
    return ConfYamlLoadRustFileIntoParent(root, filename);
}

/**
 * \brief Load configuration from a YAML string.
 */
int SCConfYamlLoadString(const char *string, size_t len)
{
    SCConfNode *root = SCConfGetRootNode();
    if (unlikely(root == NULL)) {
        return -1;
    }

    return ConfYamlLoadRustStringIntoParent(root, string, len);
}

/**
 * \brief Load configuration from a YAML file, insert in tree at 'prefix'
 *
 * This function will load a configuration file and insert it into the
 * config tree at 'prefix'. This means that if this is called with prefix
 * "abc" and the file contains a parameter "def", it will be loaded as
 * "abc.def".
 *
 * \param filename Filename of configuration file to load.
 * \param prefix Name prefix to use.
 *
 * \retval 0 on success, -1 on failure.
 */
int SCConfYamlLoadFileWithPrefix(const char *filename, const char *prefix)
{
    if (unlikely(filename == NULL || prefix == NULL)) {
        return -1;
    }

    struct stat stat_buf;
    if (stat(filename, &stat_buf) == 0) {
        if (stat_buf.st_mode & S_IFDIR) {
            SCLogError("yaml argument is not a file but a directory: %s. "
                       "Please specify the yaml file in your -c option.",
                    filename);
            return -1;
        }
    }

    if (conf_dirname == NULL) {
        ConfYamlSetConfDirname(filename);
    }

    SCConfNode *root = SCConfGetNode(prefix);
    if (root == NULL) {
        /* if node at 'prefix' doesn't yet exist, add a place holder */
        SCConfSet(prefix, "<prefix root node>");
        root = SCConfGetNode(prefix);
        if (root == NULL) {
            return -1;
        }
    }

    return ConfYamlLoadRustFileIntoParent(root, filename);
}

#ifdef UNITTESTS

#include "util-unittest-helper.h"

static int
ConfYamlSequenceTest(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
rule-files:\n\
  - netbios.rules\n\
  - x11.rules\n\
\n\
default-log-dir: /tmp\n\
";

    SCConfCreateContextBackup();
    SCConfInit();

    SCConfYamlLoadString(input, strlen(input));

    SCConfNode *node;
    node = SCConfGetNode("rule-files");
    FAIL_IF_NULL(node);
    FAIL_IF_NOT(SCConfNodeIsSequence(node));
    FAIL_IF(TAILQ_EMPTY(&node->head));
    int i = 0;
    SCConfNode *filename;
    TAILQ_FOREACH(filename, &node->head, next) {
        if (i == 0) {
            FAIL_IF(strcmp(filename->val, "netbios.rules") != 0);
            FAIL_IF(SCConfNodeIsSequence(filename));
            FAIL_IF(filename->is_seq != 0);
        }
        else if (i == 1) {
            FAIL_IF(strcmp(filename->val, "x11.rules") != 0);
            FAIL_IF(SCConfNodeIsSequence(filename));
        }
        FAIL_IF(i > 1);
        i++;
    }

    SCConfDeInit();
    SCConfRestoreContextBackup();
    PASS;
}

static int
ConfYamlLoggingOutputTest(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
logging:\n\
  output:\n\
    - interface: console\n\
      log-level: error\n\
    - interface: syslog\n\
      facility: local4\n\
      log-level: info\n\
";

    SCConfCreateContextBackup();
    SCConfInit();

    SCConfYamlLoadString(input, strlen(input));

    SCConfNode *outputs;
    outputs = SCConfGetNode("logging.output");
    FAIL_IF_NULL(outputs);

    SCConfNode *output;
    SCConfNode *output_param;

    output = TAILQ_FIRST(&outputs->head);
    FAIL_IF_NULL(output);
    FAIL_IF(strcmp(output->name, "0") != 0);

    output_param = TAILQ_FIRST(&output->head);
    FAIL_IF_NULL(output_param);
    FAIL_IF(strcmp(output_param->name, "interface") != 0);
    FAIL_IF(strcmp(output_param->val, "console") != 0);

    output_param = TAILQ_NEXT(output_param, next);
    FAIL_IF(strcmp(output_param->name, "log-level") != 0);
    FAIL_IF(strcmp(output_param->val, "error") != 0);

    output = TAILQ_NEXT(output, next);
    FAIL_IF_NULL(output);
    FAIL_IF(strcmp(output->name, "1") != 0);

    output_param = TAILQ_FIRST(&output->head);
    FAIL_IF_NULL(output_param);
    FAIL_IF(strcmp(output_param->name, "interface") != 0);
    FAIL_IF(strcmp(output_param->val, "syslog") != 0);

    output_param = TAILQ_NEXT(output_param, next);
    FAIL_IF(strcmp(output_param->name, "facility") != 0);
    FAIL_IF(strcmp(output_param->val, "local4") != 0);

    output_param = TAILQ_NEXT(output_param, next);
    FAIL_IF(strcmp(output_param->name, "log-level") != 0);
    FAIL_IF(strcmp(output_param->val, "info") != 0);

    SCConfDeInit();
    SCConfRestoreContextBackup();

    PASS;
}

/**
 * Try to load a path that is not a regular file.
 */
static int
ConfYamlNonYamlFileTest(void)
{
    SCConfCreateContextBackup();
    SCConfInit();

    FAIL_IF(SCConfYamlLoadFile(".") != -1);

    SCConfDeInit();
    SCConfRestoreContextBackup();

    PASS;
}

/**
 * Try to load invalid YAML syntax.
 */
static int
ConfYamlBadYamlVersionTest(void)
{
    char input[] = "\
logging:\n\
  output: [\n\
";

    SCConfCreateContextBackup();
    SCConfInit();

    FAIL_IF(SCConfYamlLoadString(input, strlen(input)) != -1);

    SCConfDeInit();
    SCConfRestoreContextBackup();

    PASS;
}

static int
ConfYamlSecondLevelSequenceTest(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
  server-config:\n\
    - apache-php:\n\
        address: [\"192.168.1.0/24\"]\n\
        personality: [\"Apache_2_2\", \"PHP_5_3\"]\n\
        path-parsing: [\"compress_separators\", \"lowercase\"]\n\
    - iis-php:\n\
        address:\n\
          - 192.168.0.0/24\n\
\n\
        personality:\n\
          - IIS_7_0\n\
          - PHP_5_3\n\
\n\
        path-parsing:\n\
          - compress_separators\n\
";

    SCConfCreateContextBackup();
    SCConfInit();

    FAIL_IF(SCConfYamlLoadString(input, strlen(input)) != 0);

    SCConfNode *outputs;
    outputs = SCConfGetNode("libhtp.server-config");
    FAIL_IF_NULL(outputs);

    SCConfNode *node;

    node = TAILQ_FIRST(&outputs->head);
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->name, "0") != 0);

    node = TAILQ_FIRST(&node->head);
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->name, "apache-php") != 0);

    node = SCConfNodeLookupChild(node, "address");
    FAIL_IF_NULL(node);

    node = TAILQ_FIRST(&node->head);
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->name, "0") != 0);
    FAIL_IF(strcmp(node->val, "192.168.1.0/24") != 0);

    SCConfDeInit();
    SCConfRestoreContextBackup();

    PASS;
}

/**
 * Test file inclusion support.
 */
static int
ConfYamlFileIncludeTest(void)
{
    FILE *config_file;

    const char config_filename[] = "ConfYamlFileIncludeTest-config.yaml";
    const char config_file_contents[] =
        "%YAML 1.1\n"
        "---\n"
        "# Include something at the root level.\n"
        "include: ConfYamlFileIncludeTest-include.yaml\n"
        "# Test including under a mapping.\n"
        "mapping: !include ConfYamlFileIncludeTest-include.yaml\n";

    const char include_filename[] = "ConfYamlFileIncludeTest-include.yaml";
    const char include_file_contents[] =
        "%YAML 1.1\n"
        "---\n"
        "host-mode: auto\n"
        "unix-command:\n"
        "  enabled: no\n";

    SCConfCreateContextBackup();
    SCConfInit();

    /* Write out the test files. */
    FAIL_IF_NULL((config_file = fopen(config_filename, "w")));
    FAIL_IF(fwrite(config_file_contents, strlen(config_file_contents), 1, config_file) != 1);
    fclose(config_file);

    FAIL_IF_NULL((config_file = fopen(include_filename, "w")));
    FAIL_IF(fwrite(include_file_contents, strlen(include_file_contents), 1, config_file) != 1);
    fclose(config_file);

    /* Reset conf_dirname. */
    if (conf_dirname != NULL) {
        SCFree(conf_dirname);
        conf_dirname = NULL;
    }

    FAIL_IF(SCConfYamlLoadFile("ConfYamlFileIncludeTest-config.yaml") != 0);

    /* Check values that should have been loaded into the root of the
     * configuration. */
    SCConfNode *node;
    node = SCConfGetNode("host-mode");
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->val, "auto") != 0);

    node = SCConfGetNode("unix-command.enabled");
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->val, "no") != 0);

    /* Check for values that were included under a mapping. */
    node = SCConfGetNode("mapping.host-mode");
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->val, "auto") != 0);

    node = SCConfGetNode("mapping.unix-command.enabled");
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->val, "no") != 0);

    SCConfDeInit();
    SCConfRestoreContextBackup();

    unlink(config_filename);
    unlink(include_filename);

    PASS;
}

/**
 * Test that a configuration section is overridden but subsequent
 * occurrences.
 */
static int
ConfYamlOverrideTest(void)
{
    char config[] = "%YAML 1.1\n"
                    "---\n"
                    "some-log-dir: /var/log\n"
                    "some-log-dir: /tmp\n"
                    "\n"
                    "parent:\n"
                    "  child0:\n"
                    "    key: value\n"
                    "parent:\n"
                    "  child1:\n"
                    "    key: value\n"
                    "vars:\n"
                    "  address-groups:\n"
                    "    HOME_NET: \"[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]\"\n"
                    "    EXTERNAL_NET: any\n"
                    "vars.address-groups.HOME_NET: \"10.10.10.10/32\"\n";
    const char *value;

    SCConfCreateContextBackup();
    SCConfInit();

    FAIL_IF(SCConfYamlLoadString(config, strlen(config)) != 0);
    FAIL_IF_NOT(SCConfGet("some-log-dir", &value));
    FAIL_IF(strcmp(value, "/tmp") != 0);

    /* Test that parent.child0 does not exist, but child1 does. */
    FAIL_IF_NOT_NULL(SCConfGetNode("parent.child0"));
    FAIL_IF_NOT(SCConfGet("parent.child1.key", &value));
    FAIL_IF(strcmp(value, "value") != 0);

    /* First check that vars.address-groups.EXTERNAL_NET has the
     * expected parent of vars.address-groups and save this
     * pointer. We want to make sure that the overrided value has the
     * same parent later on. */
    SCConfNode *vars_address_groups = SCConfGetNode("vars.address-groups");
    FAIL_IF_NULL(vars_address_groups);
    SCConfNode *vars_address_groups_external_net =
            SCConfGetNode("vars.address-groups.EXTERNAL_NET");
    FAIL_IF_NULL(vars_address_groups_external_net);
    FAIL_IF_NOT(vars_address_groups_external_net->parent == vars_address_groups);

    /* Now check that HOME_NET has the overrided value. */
    SCConfNode *vars_address_groups_home_net = SCConfGetNode("vars.address-groups.HOME_NET");
    FAIL_IF_NULL(vars_address_groups_home_net);
    FAIL_IF(strcmp(vars_address_groups_home_net->val, "10.10.10.10/32") != 0);

    /* And check that it has the correct parent. */
    FAIL_IF_NOT(vars_address_groups_home_net->parent == vars_address_groups);

    SCConfDeInit();
    SCConfRestoreContextBackup();

    PASS;
}

/**
 * Test that a configuration parameter loaded from YAML doesn't
 * override a 'final' value that may be set on the command line.
 */
static int
ConfYamlOverrideFinalTest(void)
{
    SCConfCreateContextBackup();
    SCConfInit();

    char config[] =
        "%YAML 1.1\n"
        "---\n"
        "default-log-dir: /var/log\n";

    /* Set the log directory as if it was set on the command line. */
    FAIL_IF_NOT(SCConfSetFinal("default-log-dir", "/tmp"));
    FAIL_IF(SCConfYamlLoadString(config, strlen(config)) != 0);

    const char *default_log_dir;

    FAIL_IF_NOT(SCConfGet("default-log-dir", &default_log_dir));
    FAIL_IF(strcmp(default_log_dir, "/tmp") != 0);

    SCConfDeInit();
    SCConfRestoreContextBackup();

    PASS;
}

static int ConfYamlNull(void)
{
    SCConfCreateContextBackup();
    SCConfInit();

    char config[] = "%YAML 1.1\n"
                    "---\n"
                    "quoted-tilde: \"~\"\n"
                    "unquoted-tilde: ~\n"
                    "quoted-null: \"null\"\n"
                    "unquoted-null: null\n"
                    "quoted-Null: \"Null\"\n"
                    "unquoted-Null: Null\n"
                    "quoted-NULL: \"NULL\"\n"
                    "unquoted-NULL: NULL\n"
                    "empty-quoted: \"\"\n"
                    "empty-unquoted: \n"
                    "list: [\"null\", null, \"Null\", Null, \"NULL\", NULL, \"~\", ~]\n";
    FAIL_IF(SCConfYamlLoadString(config, strlen(config)) != 0);

    const char *val;

    FAIL_IF_NOT(SCConfGet("quoted-tilde", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(SCConfGet("unquoted-tilde", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(SCConfGet("quoted-null", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(SCConfGet("unquoted-null", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(SCConfGet("quoted-Null", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(SCConfGet("unquoted-Null", &val));
    FAIL_IF_NULL(val);

    FAIL_IF_NOT(SCConfGet("quoted-NULL", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(SCConfGet("unquoted-NULL", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(SCConfGet("empty-quoted", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(SCConfGet("empty-unquoted", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(SCConfGet("list.0", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(SCConfGet("list.1", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(SCConfGet("list.2", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(SCConfGet("list.3", &val));
    FAIL_IF_NULL(val);

    FAIL_IF_NOT(SCConfGet("list.4", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(SCConfGet("list.5", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(SCConfGet("list.6", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(SCConfGet("list.7", &val));
    FAIL_IF_NOT_NULL(val);

    SCConfDeInit();
    SCConfRestoreContextBackup();

    PASS;
}

/**
 * Load a configuration string into a fresh configuration context and run
 * the checks. The context is always restored, even if a check fails, so a
 * failure doesn't break later tests.
 */
static int ConfYamlLoadStringAndCheck(const char *config, int (*check)(void))
{
    SCConfCreateContextBackup();
    SCConfInit();

    int result = SCConfYamlLoadString(config, strlen(config)) == 0 && check();

    SCConfDeInit();
    SCConfRestoreContextBackup();

    return result;
}

/**
 * Write a configuration file and an include file, load the configuration
 * file into a fresh configuration context and run the checks. The context
 * is always restored and the files removed, even if a check fails.
 */
static int ConfYamlLoadFilesAndCheck(const char *config_filename, const char *config,
        const char *include_filename, const char *include, int (*check)(void))
{
    int result = 0;

    SCConfCreateContextBackup();
    SCConfInit();

    /* Reset conf_dirname. */
    if (conf_dirname != NULL) {
        SCFree(conf_dirname);
        conf_dirname = NULL;
    }

    if (TestHelperBufferToFile(config_filename, (const uint8_t *)config, strlen(config)) == 0 &&
            TestHelperBufferToFile(include_filename, (const uint8_t *)include, strlen(include)) ==
                    0) {
        result = SCConfYamlLoadFile(config_filename) == 0 && check();
    }

    SCConfDeInit();
    SCConfRestoreContextBackup();

    unlink(config_filename);
    unlink(include_filename);

    return result;
}

static int ConfYamlDottedOverrideSequenceCheck(void)
{
    const char *value;

    SCConfNode *outputs = SCConfGetNode("outputs");
    FAIL_IF_NULL(outputs);
    FAIL_IF_NOT(SCConfNodeIsSequence(outputs));

    /* The first entry is untouched. */
    FAIL_IF_NOT(SCConfGet("outputs.0", &value));
    FAIL_IF(strcmp(value, "fast") != 0);
    FAIL_IF_NOT(SCConfGet("outputs.0.fast.enabled", &value));
    FAIL_IF(strcmp(value, "yes") != 0);

    /* The second entry has the overridden value and keeps its siblings. */
    FAIL_IF_NOT(SCConfGet("outputs.1", &value));
    FAIL_IF(strcmp(value, "eve-log") != 0);
    FAIL_IF_NOT(SCConfGet("outputs.1.eve-log.enabled", &value));
    FAIL_IF(strcmp(value, "no") != 0);
    FAIL_IF_NOT(SCConfGet("outputs.1.eve-log.filetype", &value));
    FAIL_IF(strcmp(value, "regular") != 0);

    PASS;
}

/**
 * Test that a dotted key can override a value inside a sequence entry
 * by index without replacing the sequence.
 */
static int ConfYamlDottedOverrideSequenceTest(void)
{
    const char config[] = "%YAML 1.1\n"
                          "---\n"
                          "outputs:\n"
                          "  - fast:\n"
                          "      enabled: yes\n"
                          "  - eve-log:\n"
                          "      enabled: yes\n"
                          "      filetype: regular\n"
                          "outputs.1.eve-log.enabled: no\n";

    FAIL_IF_NOT(ConfYamlLoadStringAndCheck(config, ConfYamlDottedOverrideSequenceCheck));
    PASS;
}

static int ConfYamlDottedOverrideMappingMergeCheck(void)
{
    const char *value;

    FAIL_IF_NOT(SCConfGet("vars.address-groups.HOME_NET", &value));
    FAIL_IF(strcmp(value, "10.10.10.10/32") != 0);
    FAIL_IF_NOT(SCConfGet("vars.address-groups.EXTERNAL_NET", &value));
    FAIL_IF(strcmp(value, "!$HOME_NET") != 0);

    PASS;
}

/**
 * Test that a dotted key with a mapping value merges into the existing
 * mapping rather than replacing it.
 */
static int ConfYamlDottedOverrideMappingMergeTest(void)
{
    const char config[] = "%YAML 1.1\n"
                          "---\n"
                          "vars:\n"
                          "  address-groups:\n"
                          "    HOME_NET: \"[192.168.0.0/16]\"\n"
                          "    EXTERNAL_NET: \"!$HOME_NET\"\n"
                          "vars.address-groups:\n"
                          "  HOME_NET: \"10.10.10.10/32\"\n";

    FAIL_IF_NOT(ConfYamlLoadStringAndCheck(config, ConfYamlDottedOverrideMappingMergeCheck));
    PASS;
}

static int ConfYamlIncludeAfterDottedOverrideCheck(void)
{
    const char *value;

    /* The include came last, so its vars mapping replaces everything
     * before it, including the dotted override. */
    FAIL_IF_NOT(SCConfGet("vars.address-groups.HOME_NET", &value));
    FAIL_IF(strcmp(value, "3.3.3.3") != 0);
    FAIL_IF_NOT_NULL(SCConfGetNode("vars.address-groups.EXTERNAL_NET"));

    PASS;
}

/**
 * Test that an included mapping replaces a dotted override that came
 * before the include.
 */
static int ConfYamlIncludeAfterDottedOverrideTest(void)
{
    const char config_filename[] = "ConfYamlIncludeAfterDottedOverrideTest-config.yaml";
    const char config[] = "%YAML 1.1\n"
                          "---\n"
                          "vars:\n"
                          "  address-groups:\n"
                          "    HOME_NET: \"1.1.1.1\"\n"
                          "    EXTERNAL_NET: any\n"
                          "vars.address-groups.HOME_NET: \"2.2.2.2\"\n"
                          "include: ConfYamlIncludeAfterDottedOverrideTest-include.yaml\n";

    const char include_filename[] = "ConfYamlIncludeAfterDottedOverrideTest-include.yaml";
    const char include[] = "%YAML 1.1\n"
                           "---\n"
                           "vars:\n"
                           "  address-groups:\n"
                           "    HOME_NET: \"3.3.3.3\"\n";

    FAIL_IF_NOT(ConfYamlLoadFilesAndCheck(config_filename, config, include_filename, include,
            ConfYamlIncludeAfterDottedOverrideCheck));
    PASS;
}

static int ConfYamlIncludeDottedOverrideOrderCheck(void)
{
    const char *value;

    /* The dotted override in the include came last, so it wins. */
    FAIL_IF_NOT(SCConfGet("vars.address-groups.HOME_NET", &value));
    FAIL_IF(strcmp(value, "3.3.3.3") != 0);

    PASS;
}

/**
 * Test that a dotted override from an include is applied after the
 * values that came before the include, even when the same dotted key
 * was also used earlier.
 */
static int ConfYamlIncludeDottedOverrideOrderTest(void)
{
    const char config_filename[] = "ConfYamlIncludeDottedOverrideOrderTest-config.yaml";
    const char config[] = "%YAML 1.1\n"
                          "---\n"
                          "vars.address-groups.HOME_NET: \"1.1.1.1\"\n"
                          "vars:\n"
                          "  address-groups:\n"
                          "    HOME_NET: \"2.2.2.2\"\n"
                          "include: ConfYamlIncludeDottedOverrideOrderTest-include.yaml\n";

    const char include_filename[] = "ConfYamlIncludeDottedOverrideOrderTest-include.yaml";
    const char include[] = "%YAML 1.1\n"
                           "---\n"
                           "vars.address-groups.HOME_NET: \"3.3.3.3\"\n";

    FAIL_IF_NOT(ConfYamlLoadFilesAndCheck(config_filename, config, include_filename, include,
            ConfYamlIncludeDottedOverrideOrderCheck));
    PASS;
}

/**
 * Write a configuration file and an additional configuration file, load
 * the configuration file into a fresh configuration context, include the
 * additional file like --include does and run the checks. The context is
 * always restored and the files removed, even if a check fails.
 */
static int ConfYamlLoadAndIncludeAndCheck(const char *config_filename, const char *config,
        const char *additional_filename, const char *additional, int (*check)(void))
{
    int result = 0;

    SCConfCreateContextBackup();
    SCConfInit();

    /* Reset conf_dirname. */
    if (conf_dirname != NULL) {
        SCFree(conf_dirname);
        conf_dirname = NULL;
    }

    if (TestHelperBufferToFile(config_filename, (const uint8_t *)config, strlen(config)) == 0 &&
            TestHelperBufferToFile(
                    additional_filename, (const uint8_t *)additional, strlen(additional)) == 0) {
        result = SCConfYamlLoadFile(config_filename) == 0 &&
                 SCConfYamlHandleInclude(SCConfGetRootNode(), additional_filename) == 0 && check();
    }

    SCConfDeInit();
    SCConfRestoreContextBackup();

    unlink(config_filename);
    unlink(additional_filename);

    return result;
}

static int ConfYamlHandleIncludeDottedOverrideCheck(void)
{
    const char *value;

    /* Only the values set by the dotted keys changed. */
    FAIL_IF_NOT(SCConfGet("vars.address-groups.HOME_NET", &value));
    FAIL_IF(strcmp(value, "10.0.0.0/8") != 0);
    FAIL_IF_NOT(SCConfGet("vars.address-groups.EXTERNAL_NET", &value));
    FAIL_IF(strcmp(value, "!$HOME_NET") != 0);
    FAIL_IF_NOT(SCConfGet("vars.port-groups.HTTP_PORTS", &value));
    FAIL_IF(strcmp(value, "80") != 0);

    /* The outputs are still a sequence, in the same order and with the
     * same entry names. */
    SCConfNode *outputs = SCConfGetNode("outputs");
    FAIL_IF_NULL(outputs);
    FAIL_IF_NOT(SCConfNodeIsSequence(outputs));
    SCConfNode *first = TAILQ_FIRST(&outputs->head);
    FAIL_IF_NULL(first);
    FAIL_IF(strcmp(first->name, "0") != 0);

    FAIL_IF_NOT(SCConfGet("outputs.0", &value));
    FAIL_IF(strcmp(value, "fast") != 0);
    FAIL_IF_NOT(SCConfGet("outputs.0.fast.enabled", &value));
    FAIL_IF(strcmp(value, "yes") != 0);
    FAIL_IF_NOT(SCConfGet("outputs.0.fast.filename", &value));
    FAIL_IF(strcmp(value, "fast.log") != 0);

    FAIL_IF_NOT(SCConfGet("outputs.1", &value));
    FAIL_IF(strcmp(value, "eve-log") != 0);
    FAIL_IF_NOT(SCConfGet("outputs.1.eve-log.enabled", &value));
    FAIL_IF(strcmp(value, "no") != 0);
    FAIL_IF_NOT(SCConfGet("outputs.1.eve-log.filetype", &value));
    FAIL_IF(strcmp(value, "regular") != 0);

    PASS;
}

/**
 * Test that dotted keys in an additional configuration file (--include)
 * set values in the already loaded configuration without replacing the
 * mappings and sequences along the path.
 */
static int ConfYamlHandleIncludeDottedOverrideTest(void)
{
    const char config_filename[] = "ConfYamlHandleIncludeDottedOverrideTest-config.yaml";
    const char config[] = "%YAML 1.1\n"
                          "---\n"
                          "vars:\n"
                          "  address-groups:\n"
                          "    HOME_NET: \"[192.168.0.0/16]\"\n"
                          "    EXTERNAL_NET: \"!$HOME_NET\"\n"
                          "  port-groups:\n"
                          "    HTTP_PORTS: \"80\"\n"
                          "outputs:\n"
                          "  - fast:\n"
                          "      enabled: yes\n"
                          "  - eve-log:\n"
                          "      enabled: yes\n"
                          "      filetype: regular\n";

    const char additional_filename[] = "ConfYamlHandleIncludeDottedOverrideTest-additional.yaml";
    const char additional[] = "%YAML 1.1\n"
                              "---\n"
                              "vars.address-groups.HOME_NET: \"10.0.0.0/8\"\n"
                              "outputs.0.fast:\n"
                              "  filename: fast.log\n"
                              "outputs.1.eve-log.enabled: no\n";

    FAIL_IF_NOT(ConfYamlLoadAndIncludeAndCheck(config_filename, config, additional_filename,
            additional, ConfYamlHandleIncludeDottedOverrideCheck));
    PASS;
}

#define NESTED_INCLUDE_DIR    "ConfYamlNestedIncludeTest-dir"
#define NESTED_INCLUDE_CONFIG "ConfYamlNestedIncludeTest-config.yaml"
#define NESTED_INCLUDE_ONE    NESTED_INCLUDE_DIR "/one.yaml"
#define NESTED_INCLUDE_TWO    NESTED_INCLUDE_DIR "/two.yaml"
#define NESTED_INCLUDE_TAGGED NESTED_INCLUDE_DIR "/tagged.yaml"

/**
 * Write a top-level configuration file and a set of files in a
 * subdirectory that include each other by paths relative to the
 * top-level configuration directory. Then load the configuration file
 * into a fresh configuration context, optionally include an additional
 * file like --include does, and run the checks. The context is always
 * restored and the files removed, even if a check fails.
 */
static int ConfYamlNestedIncludeLoadAndCheck(
        const char *config, const char *additional, int (*check)(void))
{
    /* The include paths are relative to the top-level configuration
     * directory, not to the directory of the including file. */
    const char one[] = "%YAML 1.1\n"
                       "---\n"
                       "from-one: one\n"
                       "from-tag: !include " NESTED_INCLUDE_TAGGED "\n"
                       "include: " NESTED_INCLUDE_TWO "\n";
    const char two[] = "%YAML 1.1\n"
                       "---\n"
                       "from-two: two\n";
    const char tagged[] = "%YAML 1.1\n"
                          "---\n"
                          "source: nested-tag\n";
    int result = 0;

    SCConfCreateContextBackup();
    SCConfInit();

    /* Reset conf_dirname. */
    if (conf_dirname != NULL) {
        SCFree(conf_dirname);
        conf_dirname = NULL;
    }

    if ((SCDefaultMkDir(NESTED_INCLUDE_DIR) == 0 || errno == EEXIST) &&
            TestHelperBufferToFile(
                    NESTED_INCLUDE_CONFIG, (const uint8_t *)config, strlen(config)) == 0 &&
            TestHelperBufferToFile(NESTED_INCLUDE_ONE, (const uint8_t *)one, strlen(one)) == 0 &&
            TestHelperBufferToFile(NESTED_INCLUDE_TWO, (const uint8_t *)two, strlen(two)) == 0 &&
            TestHelperBufferToFile(
                    NESTED_INCLUDE_TAGGED, (const uint8_t *)tagged, strlen(tagged)) == 0) {
        result = SCConfYamlLoadFile(NESTED_INCLUDE_CONFIG) == 0 &&
                 (additional == NULL ||
                         SCConfYamlHandleInclude(SCConfGetRootNode(), additional) == 0) &&
                 check();
    }

    SCConfDeInit();
    SCConfRestoreContextBackup();

    unlink(NESTED_INCLUDE_CONFIG);
    unlink(NESTED_INCLUDE_ONE);
    unlink(NESTED_INCLUDE_TWO);
    unlink(NESTED_INCLUDE_TAGGED);
    rmdir(NESTED_INCLUDE_DIR);

    return result;
}

static int ConfYamlNestedIncludeCheck(void)
{
    const char *value;

    FAIL_IF_NOT(SCConfGet("base", &value));
    FAIL_IF(strcmp(value, "root") != 0);
    FAIL_IF_NOT(SCConfGet("from-one", &value));
    FAIL_IF(strcmp(value, "one") != 0);
    FAIL_IF_NOT(SCConfGet("from-two", &value));
    FAIL_IF(strcmp(value, "two") != 0);
    FAIL_IF_NOT(SCConfGet("from-tag.source", &value));
    FAIL_IF(strcmp(value, "nested-tag") != 0);

    PASS;
}

/**
 * Test that includes in an included file are resolved relative to the
 * directory of the top-level configuration file, not to the directory
 * of the included file.
 */
static int ConfYamlNestedIncludeTest(void)
{
    const char config[] = "%YAML 1.1\n"
                          "---\n"
                          "base: root\n"
                          "include: " NESTED_INCLUDE_ONE "\n";

    FAIL_IF_NOT(ConfYamlNestedIncludeLoadAndCheck(config, NULL, ConfYamlNestedIncludeCheck));
    PASS;
}

/**
 * Test that includes in an additional configuration file (--include) are
 * resolved relative to the directory of the top-level configuration
 * file, not to the directory of the additional file.
 */
static int ConfYamlHandleIncludeNestedTest(void)
{
    const char config[] = "%YAML 1.1\n"
                          "---\n"
                          "base: root\n";

    FAIL_IF_NOT(ConfYamlNestedIncludeLoadAndCheck(
            config, NESTED_INCLUDE_ONE, ConfYamlNestedIncludeCheck));
    PASS;
}

/**
 * Load a configuration string into a fresh configuration context and
 * return the result of loading it. The context is always restored.
 */
static int ConfYamlLoadStringResult(const char *config)
{
    SCConfCreateContextBackup();
    SCConfInit();

    int ret = SCConfYamlLoadString(config, strlen(config));

    SCConfDeInit();
    SCConfRestoreContextBackup();

    return ret;
}

/**
 * Build a configuration with depth levels of nested mappings, counting
 * the root mapping, like "key: {a: {a: 1}}" for a depth of 3. The value
 * 1 is at "key" followed by depth - 1 times ".a".
 */
static char *ConfYamlNestedMappings(int depth)
{
    const size_t len = 32 + (size_t)depth * 5;
    char *config = SCCalloc(1, len);
    if (config == NULL) {
        return NULL;
    }

    strlcpy(config, "%YAML 1.1\n---\nkey: ", len);
    for (int i = 1; i < depth; i++) {
        strlcat(config, "{a: ", len);
    }
    strlcat(config, "1", len);
    for (int i = 1; i < depth; i++) {
        strlcat(config, "}", len);
    }
    strlcat(config, "\n", len);

    return config;
}

static int ConfYamlNestingLimitCheck(void)
{
    char name[16 + 128 * 2];
    const char *value;

    strlcpy(name, "key", sizeof(name));
    for (int i = 1; i < 128; i++) {
        strlcat(name, ".a", sizeof(name));
    }
    FAIL_IF_NOT(SCConfGet(name, &value));
    FAIL_IF(strcmp(value, "1") != 0);

    PASS;
}

/**
 * Test that a configuration nested 128 levels deep, counting the root
 * mapping, loads, and that one nested 129 levels deep fails to load.
 */
static int ConfYamlNestingLimitTest(void)
{
    char *config = ConfYamlNestedMappings(128);
    FAIL_IF_NULL(config);
    int ret = ConfYamlLoadStringAndCheck(config, ConfYamlNestingLimitCheck);
    SCFree(config);
    FAIL_IF_NOT(ret);

    config = ConfYamlNestedMappings(129);
    FAIL_IF_NULL(config);
    ret = ConfYamlLoadStringResult(config);
    SCFree(config);
    FAIL_IF(ret == 0);

    PASS;
}

/**
 * Test that a configuration nested far beyond the limit fails to load
 * cleanly.
 */
static int ConfYamlDeepNestingTest(void)
{
    const int depth = 1000;
    const size_t len = 32 + (size_t)depth * 2;
    char *config = SCCalloc(1, len);
    FAIL_IF_NULL(config);

    /* Compact nested sequences: "key:\n  - - - x\n". */
    strlcpy(config, "%YAML 1.1\n---\nkey:\n  ", len);
    for (int i = 0; i < depth; i++) {
        strlcat(config, "- ", len);
    }
    strlcat(config, "x\n", len);

    int ret = ConfYamlLoadStringResult(config);
    SCFree(config);
    FAIL_IF(ret == 0);

    PASS;
}

#endif /* UNITTESTS */

void SCConfYamlRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("ConfYamlSequenceTest", ConfYamlSequenceTest);
    UtRegisterTest("ConfYamlLoggingOutputTest", ConfYamlLoggingOutputTest);
    UtRegisterTest("ConfYamlNonYamlFileTest", ConfYamlNonYamlFileTest);
    UtRegisterTest("ConfYamlBadYamlVersionTest", ConfYamlBadYamlVersionTest);
    UtRegisterTest("ConfYamlSecondLevelSequenceTest",
                   ConfYamlSecondLevelSequenceTest);
    UtRegisterTest("ConfYamlFileIncludeTest", ConfYamlFileIncludeTest);
    UtRegisterTest("ConfYamlOverrideTest", ConfYamlOverrideTest);
    UtRegisterTest("ConfYamlOverrideFinalTest", ConfYamlOverrideFinalTest);
    UtRegisterTest("ConfYamlNull", ConfYamlNull);
    UtRegisterTest("ConfYamlDottedOverrideSequenceTest", ConfYamlDottedOverrideSequenceTest);
    UtRegisterTest(
            "ConfYamlDottedOverrideMappingMergeTest", ConfYamlDottedOverrideMappingMergeTest);
    UtRegisterTest(
            "ConfYamlIncludeAfterDottedOverrideTest", ConfYamlIncludeAfterDottedOverrideTest);
    UtRegisterTest(
            "ConfYamlIncludeDottedOverrideOrderTest", ConfYamlIncludeDottedOverrideOrderTest);
    UtRegisterTest(
            "ConfYamlHandleIncludeDottedOverrideTest", ConfYamlHandleIncludeDottedOverrideTest);
    UtRegisterTest("ConfYamlNestedIncludeTest", ConfYamlNestedIncludeTest);
    UtRegisterTest("ConfYamlHandleIncludeNestedTest", ConfYamlHandleIncludeNestedTest);
    UtRegisterTest("ConfYamlNestingLimitTest", ConfYamlNestingLimitTest);
    UtRegisterTest("ConfYamlDeepNestingTest", ConfYamlDeepNestingTest);
#endif /* UNITTESTS */
}
