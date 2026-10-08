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
 * YAML configuration loader.
 *
 * The configuration is loaded with the Rust suricata-config crate,
 * which does all the merging (the main file, include keys, the
 * --include files, dotted keys) and applies the command line overrides
 * (--set and the options that set a value), and the resulting tree is
 * mirrored into the SCConfNode tree. The overridden nodes are marked
 * final afterwards, so that SCConfSet does not change them and
 * SCConfNodeIsFinal sees them.
 *
 * An override that names a child of a sequence, like pcap.buffer-size
 * where pcap is a sequence of interfaces, has no place in the Rust
 * tree and is set in the SCConfNode tree after the mirror instead,
 * where a sequence node can have named children, as the libyaml based
 * loader left it.
 *
 * The mirror follows the rules of the previous libyaml based loader
 * for nodes that already exist, set with SCConfSet or SCConfSetFinal
 * before the load (Suricata itself no longer does, its command line
 * values are all overrides): an existing final node keeps its value,
 * an existing node that is not final is pruned and reused.
 */

#include "suricata-common.h"
#include "conf.h"
#include "conf-yaml-loader.h"
#include "rust-config.h"
#include "util-path.h"
#include "util-debug.h"

/* The name of a sequence item is its index, which fits in this. */
#define SEQ_NAME_LEN 32

static char *conf_dirname = NULL;

static int ConfYamlMirror(SCConfNode *parent, const SCConfTreeNode *node);

/**
 * \brief Set the directory name of the configuration file.
 *
 * \param filename The configuration filename.
 */
static void
ConfYamlSetConfDirname(const char *filename)
{
    const char *ep;

    ep = strrchr(filename, '\\');
    if (ep == NULL)
        ep = strrchr(filename, '/');

    if (ep == NULL) {
        conf_dirname = SCStrdup(".");
        if (conf_dirname == NULL) {
            FatalError("ERROR: Failed to allocate memory while loading configuration.");
        }
    }
    else {
        conf_dirname = SCStrdup(filename);
        if (conf_dirname == NULL) {
            FatalError("ERROR: Failed to allocate memory while loading configuration.");
        }
        conf_dirname[ep - filename] = '\0';
    }
}

/**
 * \brief Copy a string from the loaded tree, which is not NUL
 *     terminated. SCStrndup can't be used, its fallback reads the
 *     source as a C string.
 */
static char *ConfYamlStrndup(const char *s, size_t len)
{
    char *copy = SCMalloc(len + 1);
    if (unlikely(copy == NULL)) {
        return NULL;
    }
    memcpy(copy, s, len);
    copy[len] = '\0';
    return copy;
}

/**
 * \brief Look up a child by a name that is not NUL terminated.
 */
static SCConfNode *ConfYamlLookupChild(const SCConfNode *parent, const char *name, size_t name_len)
{
    SCConfNode *node;
    TAILQ_FOREACH (node, &parent->head, next) {
        if (node->name != NULL && strlen(node->name) == name_len &&
                memcmp(node->name, name, name_len) == 0) {
            return node;
        }
    }
    return NULL;
}

/**
 * \brief Create a child node with a name that is not NUL terminated.
 */
static SCConfNode *ConfYamlNodeNew(SCConfNode *parent, const char *name, size_t name_len)
{
    SCConfNode *node = SCConfNodeNew();
    if (unlikely(node == NULL)) {
        return NULL;
    }
    node->name = ConfYamlStrndup(name, name_len);
    if (unlikely(node->name == NULL)) {
        SCConfNodeFree(node);
        return NULL;
    }
    node->parent = parent;
    TAILQ_INSERT_TAIL(&parent->head, node, next);
    return node;
}

/**
 * \brief Set the value of a node from a scalar in the loaded tree.
 */
static int ConfYamlSetValue(SCConfNode *node, const SCConfTreeNode *scalar)
{
    size_t len = 0;
    const char *value = SCConfTreeNodeScalar(scalar, &len);
    if (value == NULL) {
        return 0;
    }
    if (node->val != NULL) {
        SCFree(node->val);
    }
    node->val = ConfYamlStrndup(value, len);
    if (unlikely(node->val == NULL)) {
        return -1;
    }
    return 0;
}

/**
 * \brief Mirror a mapping of the loaded tree below a node.
 *
 * Each entry finds or creates the child with its name. An existing
 * child that is final keeps its value, like the libyaml loader did
 * for values set from the command line, but a mapping or sequence
 * value is still mirrored below it. An existing child that is not
 * final is pruned and reused.
 */
static int ConfYamlMirrorMapping(SCConfNode *parent, const SCConfTreeNode *mapping)
{
    size_t len = SCConfTreeNodeLen(mapping);
    for (size_t i = 0; i < len; i++) {
        const char *key = NULL;
        size_t key_len = 0;
        const SCConfTreeNode *value = SCConfTreeNodeItem(mapping, i, &key, &key_len);
        if (value == NULL) {
            return -1;
        }

        /* A mapping in a sequence has its first key as its value. */
        if (parent->is_seq && parent->val == NULL && i == 0) {
            parent->val = ConfYamlStrndup(key, key_len);
            if (unlikely(parent->val == NULL)) {
                return -1;
            }
        }

        SCConfNode *node = NULL;
        SCConfNode *existing = ConfYamlLookupChild(parent, key, key_len);
        if (existing != NULL) {
            if (!existing->final) {
                SCLogInfo("Configuration node '%s' redefined.", existing->name);
                SCConfNodePrune(existing);
            }
            node = existing;
        } else {
            node = ConfYamlNodeNew(parent, key, key_len);
            if (unlikely(node == NULL)) {
                return -1;
            }
        }

        switch (SCConfTreeNodeKind(value)) {
            case SC_CONF_TREE_KIND_NULL:
                break;
            case SC_CONF_TREE_KIND_SCALAR:
                if (!node->final && ConfYamlSetValue(node, value) != 0) {
                    return -1;
                }
                break;
            case SC_CONF_TREE_KIND_SEQUENCE:
            case SC_CONF_TREE_KIND_MAPPING:
                if (ConfYamlMirror(node, value) != 0) {
                    return -1;
                }
                break;
        }
    }
    return 0;
}

/**
 * \brief Mirror a sequence of the loaded tree below a node.
 *
 * Items are children named by their index. If the node already had
 * children, an existing item is reused and moved to the end, so the
 * items iterate in document order, and its value is kept.
 */
static int ConfYamlMirrorSequence(SCConfNode *parent, const SCConfTreeNode *sequence)
{
    const bool was_empty = TAILQ_EMPTY(&parent->head);
    size_t len = SCConfTreeNodeLen(sequence);

    parent->is_seq = 1;

    for (size_t i = 0; i < len; i++) {
        const char *key = NULL;
        size_t key_len = 0;
        const SCConfTreeNode *item = SCConfTreeNodeItem(sequence, i, &key, &key_len);
        if (item == NULL) {
            return -1;
        }

        char name[SEQ_NAME_LEN];
        snprintf(name, sizeof(name), "%" PRIuMAX, (uintmax_t)i);
        SCConfNode *node = NULL;
        /* Only look up existing items if the node had children, to
         * keep long sequences linear. */
        if (!was_empty) {
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
            // do not fuzz quadratic-complexity overlong sequence of scalars
            if (i > 256) {
                return -1;
            }
#endif
            node = SCConfNodeLookupChild(parent, name);
        }
        if (node != NULL) {
            /* The sequence node has already been set, probably from
             * the command line. Move it to the end so it is iterated
             * in the expected order. */
            TAILQ_REMOVE(&parent->head, node, next);
            TAILQ_INSERT_TAIL(&parent->head, node, next);
        } else {
            node = ConfYamlNodeNew(parent, name, strlen(name));
            if (unlikely(node == NULL)) {
                return -1;
            }
            if (SCConfTreeNodeKind(item) == SC_CONF_TREE_KIND_SCALAR &&
                    ConfYamlSetValue(node, item) != 0) {
                return -1;
            }
        }

        switch (SCConfTreeNodeKind(item)) {
            case SC_CONF_TREE_KIND_NULL:
            case SC_CONF_TREE_KIND_SCALAR:
                break;
            case SC_CONF_TREE_KIND_MAPPING:
                /* A mapping item is a sequence node in the C tree, for
                 * its first key to be its value. */
                node->is_seq = 1;
                if (ConfYamlMirror(node, item) != 0) {
                    return -1;
                }
                break;
            case SC_CONF_TREE_KIND_SEQUENCE:
                if (ConfYamlMirror(node, item) != 0) {
                    return -1;
                }
                break;
        }
    }
    return 0;
}

/**
 * \brief Mirror a mapping or sequence of the loaded tree below a node.
 */
static int ConfYamlMirror(SCConfNode *parent, const SCConfTreeNode *node)
{
    switch (SCConfTreeNodeKind(node)) {
        case SC_CONF_TREE_KIND_MAPPING:
            return ConfYamlMirrorMapping(parent, node);
        case SC_CONF_TREE_KIND_SEQUENCE:
            return ConfYamlMirrorSequence(parent, node);
        case SC_CONF_TREE_KIND_NULL:
        case SC_CONF_TREE_KIND_SCALAR:
            break;
    }
    return 0;
}

/**
 * \brief Mark the node at a dotted path below a node as final.
 */
static void ConfYamlSetFinal(SCConfNode *root, const char *path, size_t path_len)
{
    SCConfNode *node = root;
    const char *end = path + path_len;
    while (node != NULL) {
        const char *dot = memchr(path, '.', end - path);
        size_t len = dot != NULL ? (size_t)(dot - path) : (size_t)(end - path);
        node = ConfYamlLookupChild(node, path, len);
        if (dot == NULL) {
            break;
        }
        path = dot + 1;
    }
    if (node != NULL) {
        node->final = 1;
    }
}

/**
 * \brief The number of entries of a NULL terminated array.
 */
static size_t ConfYamlCount(const char *const *array)
{
    size_t n = 0;
    if (array != NULL) {
        while (array[n] != NULL) {
            n++;
        }
    }
    return n;
}

/**
 * \brief Set a value at a dotted path below a node, final, like
 *     SCConfSetFinal does below the root.
 */
static int ConfYamlSetFinalValue(SCConfNode *root, const char *path, const char *value)
{
    SCConfNode *node = SCConfNodeGetNodeOrCreate(root, path, 1);
    if (node == NULL) {
        return -1;
    }
    if (node->val != NULL) {
        SCFree(node->val);
    }
    node->val = SCStrdup(value);
    if (unlikely(node->val == NULL)) {
        return -1;
    }
    node->final = 1;
    return 0;
}

/**
 * \brief Load a configuration file into the tree at a node.
 *
 * \param filename Filename of the configuration file to load.
 * \param includes NULL terminated list of files to load after it, as
 *     with --include, or NULL.
 * \param override_paths NULL terminated list of the dotted paths of the
 *     command line overrides, applied after the load, or NULL.
 * \param override_values Their values, in the same order.
 * \param root The node to load the configuration below.
 *
 * \retval 0 on success, -1 on failure.
 */
static int ConfYamlLoadFile(const char *filename, const char *const *includes,
        const char *const *override_paths, const char *const *override_values, SCConfNode *root)
{
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

    size_t n_overrides = ConfYamlCount(override_paths);
    BUG_ON(n_overrides != ConfYamlCount(override_values));

    char *err = NULL;
    SCConfTree *tree = SCConfTreeLoadFile(filename, conf_dirname, includes, ConfYamlCount(includes),
            override_paths, override_values, n_overrides, &err);
    if (tree == NULL) {
        SCLogError("%s", err != NULL ? err : "failed to load configuration file");
        SCConfTreeErrorFree(err);
        return -1;
    }

    int ret = ConfYamlMirror(root, SCConfTreeRoot(tree));
    for (size_t i = 0; ret == 0 && i < n_overrides; i++) {
        if (SCConfTreeOverrideApplied(tree, i)) {
            size_t len = 0;
            const char *path = SCConfTreeOverridePath(tree, i, &len);
            ConfYamlSetFinal(root, path, len);
        } else {
            ret = ConfYamlSetFinalValue(root, override_paths[i], override_values[i]);
        }
    }
    SCConfTreeFree(tree);
    return ret;
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
    return ConfYamlLoadFile(filename, NULL, NULL, NULL, SCConfGetRootNode());
}

/**
 * \brief Load configuration from a YAML string.
 */
int SCConfYamlLoadString(const char *string, size_t len)
{
    char *err = NULL;
    SCConfTree *tree = SCConfTreeLoadString(string, len, conf_dirname, &err);
    if (tree == NULL) {
        SCLogError("%s", err != NULL ? err : "failed to load configuration");
        SCConfTreeErrorFree(err);
        return -1;
    }

    int ret = ConfYamlMirror(SCConfGetRootNode(), SCConfTreeRoot(tree));
    SCConfTreeFree(tree);
    return ret;
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
 * \param prefix Name prefix to use, or NULL for the root.
 * \param includes NULL terminated list of files to load after it, as
 *     with --include, or NULL.
 * \param override_paths NULL terminated list of the dotted paths of the
 *     command line overrides, applied in order after the files are
 *     loaded, or NULL. The nodes set are final.
 * \param override_values Their values, in the same order.
 *
 * \retval 0 on success, -1 on failure.
 */
int SCConfYamlLoadFileWithOptions(const char *filename, const char *prefix,
        const char *const *includes, const char *const *override_paths,
        const char *const *override_values)
{
    SCConfNode *root;
    if (prefix == NULL) {
        root = SCConfGetRootNode();
    } else {
        root = SCConfGetNode(prefix);
        if (root == NULL) {
            /* if node at 'prefix' doesn't yet exist, add a place holder */
            SCConfSet(prefix, "<prefix root node>");
            root = SCConfGetNode(prefix);
            if (root == NULL) {
                return -1;
            }
        }
    }
    return ConfYamlLoadFile(filename, includes, override_paths, override_values, root);
}

/**
 * \brief Load configuration from a YAML file, insert in tree at 'prefix'
 *
 * See SCConfYamlLoadFileWithOptions.
 */
int SCConfYamlLoadFileWithPrefix(const char *filename, const char *prefix)
{
    return SCConfYamlLoadFileWithOptions(filename, prefix, NULL, NULL, NULL);
}

#ifdef UNITTESTS

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
    FAIL_IF(strcmp(output->val, "interface") != 0);

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
 * Try to load something that is not a valid YAML file.
 */
static int
ConfYamlNonYamlFileTest(void)
{
    SCConfCreateContextBackup();
    SCConfInit();

    FAIL_IF(SCConfYamlLoadFile("/etc/passwd") != -1);

    SCConfDeInit();
    SCConfRestoreContextBackup();

    PASS;
}

/**
 * Invalid YAML is an error, and loads nothing.
 */
static int ConfYamlInvalidYamlTest(void)
{
    char input[] = "a: 1\nb: [\n";

    SCConfCreateContextBackup();
    SCConfInit();

    FAIL_IF(SCConfYamlLoadString(input, strlen(input)) != -1);
    FAIL_IF_NOT_NULL(SCConfGetNode("a"));

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
    const char include_file_contents[] = "%YAML 1.1\n"
                                         "---\n"
                                         "host-mode: auto\n"
                                         "unix-command:\n"
                                         "  enabled: no\n"
                                         "list:\n"
                                         "  - a\n"
                                         "  - b\n";

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

    /* Load the include file again as a --include file, into a
     * prefix. */
    SCConfCreateContextBackup();
    SCConfInit();

    const char *includes[] = { include_filename, NULL };
    const char *paths[] = { "host-mode", "new.key", "list.00", "list.name", NULL };
    const char *values[] = { " sniffer-only", "1", "x", "y", NULL };
    FAIL_IF(SCConfYamlLoadFileWithOptions(config_filename, "prefix", includes, paths, values) != 0);
    node = SCConfGetNode("prefix.mapping.host-mode");
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->val, "auto") != 0);
    FAIL_IF_NOT_NULL(SCConfGetNode("host-mode"));

    /* The overrides are applied after the files, with the values as
     * given, and are final. */
    node = SCConfGetNode("prefix.host-mode");
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->val, " sniffer-only") != 0);
    FAIL_IF(!node->final);
    node = SCConfGetNode("prefix.new.key");
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->val, "1") != 0);
    FAIL_IF(!node->final);
    FAIL_IF(SCConfGetNode("prefix.new")->final);
    /* SCConfSet does not change a final node. */
    FAIL_IF(SCConfSet("prefix.host-mode", "auto") != 0);
    node = SCConfGetNode("prefix.host-mode");
    FAIL_IF(strcmp(node->val, " sniffer-only") != 0);

    /* An index is final under its resolved name. */
    node = SCConfGetNode("prefix.list.0");
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->val, "x") != 0);
    FAIL_IF(!node->final);
    FAIL_IF_NOT_NULL(SCConfGetNode("prefix.list.00"));

    /* A name into a sequence is set next to the items, final. */
    node = SCConfGetNode("prefix.list.name");
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->val, "y") != 0);
    FAIL_IF(!node->final);
    node = SCConfGetNode("prefix.list.1");
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->val, "b") != 0);

    /* A missing --include file is an error. */
    const char *missing[] = { "ConfYamlFileIncludeTest-missing.yaml", NULL };
    FAIL_IF(SCConfYamlLoadFileWithOptions(config_filename, "prefix2", missing, NULL, NULL) != -1);

    /* A bad override path is an error. */
    const char *bad_paths[] = { "a..b", NULL };
    const char *bad_values[] = { "1", NULL };
    FAIL_IF(SCConfYamlLoadFileWithOptions(
                    config_filename, "prefix3", NULL, bad_paths, bad_values) != -1);

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

    char config[] = "%YAML 1.1\n"
                    "---\n"
                    "default-log-dir: /var/log\n"
                    "af-packet:\n"
                    "  - interface: eth0\n"
                    "    cluster-id: 99\n"
                    "  - interface: eth1\n";

    /* Set the log directory as if it was set on the command line. */
    FAIL_IF_NOT(SCConfSetFinal("default-log-dir", "/tmp"));
    /* And a value in a sequence item, which has the item set before
     * the sequence is loaded. */
    FAIL_IF_NOT(SCConfSetFinal("af-packet.0.interface", "eth9"));
    FAIL_IF(SCConfYamlLoadString(config, strlen(config)) != 0);

    const char *value;

    FAIL_IF_NOT(SCConfGet("default-log-dir", &value));
    FAIL_IF(strcmp(value, "/tmp") != 0);

    FAIL_IF_NOT(SCConfGet("af-packet.0.interface", &value));
    FAIL_IF(strcmp(value, "eth9") != 0);
    FAIL_IF_NOT(SCConfGet("af-packet.0.cluster-id", &value));
    FAIL_IF(strcmp(value, "99") != 0);
    FAIL_IF_NOT(SCConfGet("af-packet.1.interface", &value));
    FAIL_IF(strcmp(value, "eth1") != 0);

    /* The items are in document order. */
    SCConfNode *af_packet = SCConfGetNode("af-packet");
    FAIL_IF_NULL(af_packet);
    FAIL_IF_NOT(SCConfNodeIsSequence(af_packet));
    SCConfNode *item = TAILQ_FIRST(&af_packet->head);
    FAIL_IF_NULL(item);
    FAIL_IF(strcmp(item->name, "0") != 0);
    item = TAILQ_NEXT(item, next);
    FAIL_IF_NULL(item);
    FAIL_IF(strcmp(item->name, "1") != 0);

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
    FAIL_IF_NOT_NULL(val);

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
    FAIL_IF_NOT_NULL(val);

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
 * Underscores in keys are replaced with dashes, except below
 * address-groups and port-groups.
 */
static int ConfYamlKeyManglingTest(void)
{
    SCConfCreateContextBackup();
    SCConfInit();

    char config[] = "host_os_policy:\n"
                    "  some_key: 1\n"
                    "vars:\n"
                    "  address-groups:\n"
                    "    HOME_NET: any\n"
                    "  port-groups:\n"
                    "    HTTP_PORTS: 80\n"
                    "seq_of_maps:\n"
                    "  - inter_face: eth0\n";
    FAIL_IF(SCConfYamlLoadString(config, strlen(config)) != 0);

    const char *val;
    FAIL_IF_NOT(SCConfGet("host-os-policy.some-key", &val));
    FAIL_IF(strcmp(val, "1") != 0);
    FAIL_IF_NOT_NULL(SCConfGetNode("host_os_policy"));
    FAIL_IF_NOT(SCConfGet("vars.address-groups.HOME_NET", &val));
    FAIL_IF_NOT(SCConfGet("vars.port-groups.HTTP_PORTS", &val));
    FAIL_IF_NOT(SCConfGet("seq-of-maps.0.inter-face", &val));
    FAIL_IF(strcmp(val, "eth0") != 0);
    FAIL_IF_NOT(SCConfGet("seq-of-maps.0", &val));
    FAIL_IF(strcmp(val, "inter-face") != 0);

    SCConfDeInit();
    SCConfRestoreContextBackup();

    PASS;
}

#endif /* UNITTESTS */

void SCConfYamlRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("ConfYamlSequenceTest", ConfYamlSequenceTest);
    UtRegisterTest("ConfYamlLoggingOutputTest", ConfYamlLoggingOutputTest);
    UtRegisterTest("ConfYamlNonYamlFileTest", ConfYamlNonYamlFileTest);
    UtRegisterTest("ConfYamlInvalidYamlTest", ConfYamlInvalidYamlTest);
    UtRegisterTest("ConfYamlSecondLevelSequenceTest",
                   ConfYamlSecondLevelSequenceTest);
    UtRegisterTest("ConfYamlFileIncludeTest", ConfYamlFileIncludeTest);
    UtRegisterTest("ConfYamlOverrideTest", ConfYamlOverrideTest);
    UtRegisterTest("ConfYamlOverrideFinalTest", ConfYamlOverrideFinalTest);
    UtRegisterTest("ConfYamlNull", ConfYamlNull);
    UtRegisterTest("ConfYamlKeyManglingTest", ConfYamlKeyManglingTest);
#endif /* UNITTESTS */
}
