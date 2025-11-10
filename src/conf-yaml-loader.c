/* Copyright (C) 2007-2023 Open Information Security Foundation
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
 */

#include "suricata-common.h"
#include "conf.h"
#include "conf-yaml-loader.h"
#include <yaml.h>
#include "util-path.h"
#include "util-debug.h"
#include "util-unittest.h"

#define YAML_VERSION_MAJOR 1
#define YAML_VERSION_MINOR 1

/* The maximum level of recursion allowed while parsing the YAML
 * file. */
#define RECURSION_LIMIT 128

/* Sometimes we'll have to create a node name on the fly (integer
 * conversion, etc), so this is a default length to allocate that will
 * work most of the time. */
#define DEFAULT_NAME_LEN 16

#define MANGLE_ERRORS_MAX 10
static int mangle_errors = 0;

static char *conf_dirname = NULL;

static int ConfYamlParse(yaml_parser_t *parser, ConfNode *parent, int inseq, int rlevel, int state);

/* Configuration processing states. */
enum conf_state {
    CONF_KEY = 0,
    CONF_VAL,
    CONF_INCLUDE,
};

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

    return;
}

/**
 * \brief Set the directory name of the configuration file.
 *
 * \param filename The configuration filename.
 */
static void
ConfYamlSetConfDirname(const char *filename)
{
    char *ep;

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
 * \brief Include a file in the configuration.
 *
 * \param parent The configuration node the included configuration will be
 *          placed at.
 * \param filename The filename to include.
 *
 * \retval 0 on success, -1 on failure.
 */
int ConfYamlHandleInclude(ConfNode *parent, const char *filename)
{
    yaml_parser_t parser;
    char include_filename[PATH_MAX];
    FILE *file = NULL;
    int ret = -1;

    if (yaml_parser_initialize(&parser) != 1) {
        SCLogError("Failed to initialize YAML parser");
        return -1;
    }

    if (PathIsAbsolute(filename)) {
        strlcpy(include_filename, filename, sizeof(include_filename));
    }
    else {
        snprintf(include_filename, sizeof(include_filename), "%s/%s",
            conf_dirname, filename);
    }

    file = fopen(include_filename, "r");
    if (file == NULL) {
        SCLogError("Failed to open configuration include file %s: %s", include_filename,
                strerror(errno));
        goto done;
    }

    yaml_parser_set_input_file(&parser, file);

    if (ConfYamlParse(&parser, parent, 0, 0, 0) != 0) {
        SCLogError("Failed to include configuration file %s", filename);
        goto done;
    }

    ret = 0;

done:
    yaml_parser_delete(&parser);
    if (file != NULL) {
        fclose(file);
    }

    return ret;
}

/**
 * \brief Parse a YAML layer.
 *
 * \param parser A pointer to an active yaml_parser_t.
 * \param parent The parent configuration node.
 *
 * \retval 0 on success, -1 on failure.
 */
static int ConfYamlParse(yaml_parser_t *parser, ConfNode *parent, int inseq, int rlevel, int state)
{
    ConfNode *node = parent;
    yaml_event_t event;
    memset(&event, 0, sizeof(event));
    int done = 0;
    int seq_idx = 0;
    int retval = 0;
    int was_empty = -1;
    int include_count = 0;

    if (rlevel++ > RECURSION_LIMIT) {
        SCLogError("Recursion limit reached while parsing "
                   "configuration file, aborting.");
        return -1;
    }

    while (!done) {
        if (!yaml_parser_parse(parser, &event)) {
            SCLogError("Failed to parse configuration file at line %" PRIuMAX ": %s",
                    (uintmax_t)parser->problem_mark.line, parser->problem);
            retval = -1;
            break;
        }

        if (event.type == YAML_DOCUMENT_START_EVENT) {
            SCLogDebug("event.type=YAML_DOCUMENT_START_EVENT; state=%d", state);
            /* Verify YAML version - its more likely to be a valid
             * Suricata configuration file if the version is
             * correct. */
            yaml_version_directive_t *ver =
                event.data.document_start.version_directive;
            if (ver == NULL) {
                SCLogError("ERROR: Invalid configuration file.");
                SCLogError("The configuration file must begin with the following two lines: %%YAML "
                           "1.1 and ---");
                goto fail;
            }
            int major = ver->major;
            int minor = ver->minor;
            if (!(major == YAML_VERSION_MAJOR && minor == YAML_VERSION_MINOR)) {
                SCLogError("ERROR: Invalid YAML version.  Must be 1.1");
                goto fail;
            }
        }
        else if (event.type == YAML_SCALAR_EVENT) {
            char *value = (char *)event.data.scalar.value;
            char *tag = (char *)event.data.scalar.tag;
            SCLogDebug("event.type=YAML_SCALAR_EVENT; state=%d; value=%s; "
                "tag=%s; inseq=%d", state, value, tag, inseq);

            /* Skip over empty scalar values while in KEY state. This
             * tends to only happen on an empty file, where a scalar
             * event probably shouldn't fire anyways. */
            if (state == CONF_KEY && strlen(value) == 0) {
                goto next;
            }

            /* If the value is unquoted, certain strings in YAML represent NULL. */
            if ((inseq || state == CONF_VAL) &&
                    event.data.scalar.style == YAML_PLAIN_SCALAR_STYLE) {
                if (strlen(value) == 0 || strcmp(value, "~") == 0 || strcmp(value, "null") == 0 ||
                        strcmp(value, "Null") == 0 || strcmp(value, "NULL") == 0) {
                    value = NULL;
                }
            }

            if (inseq) {
                if (state == CONF_INCLUDE) {
                    if (value != NULL) {
                        SCLogInfo("Including configuration file %s.", value);
                        if (ConfYamlHandleInclude(parent, value) != 0) {
                            goto fail;
                        }
                    }
                    goto next;
                }
                char sequence_node_name[DEFAULT_NAME_LEN];
                snprintf(sequence_node_name, DEFAULT_NAME_LEN, "%d", seq_idx++);
                ConfNode *seq_node = NULL;
                if (was_empty < 0) {
                    // initialize was_empty
                    if (TAILQ_EMPTY(&parent->head)) {
                        was_empty = 1;
                    } else {
                        was_empty = 0;
                    }
                }
                // we only check if the node's list was not empty at first
                if (was_empty == 0) {
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
                    // do not fuzz quadratic-complexity overlong sequence of scalars
                    if (seq_idx > 256) {
                        goto fail;
                    }
#endif
                    seq_node = ConfNodeLookupChild(parent, sequence_node_name);
                }
                if (seq_node != NULL) {
                    /* The sequence node has already been set, probably
                     * from the command line.  Remove it so it gets
                     * re-added in the expected order for iteration.
                     */
                    TAILQ_REMOVE(&parent->head, seq_node, next);
                }
                else {
                    seq_node = ConfNodeNew();
                    if (unlikely(seq_node == NULL)) {
                        goto fail;
                    }
                    seq_node->name = SCStrdup(sequence_node_name);
                    if (unlikely(seq_node->name == NULL)) {
                        SCFree(seq_node);
                        goto fail;
                    }
                    if (value != NULL) {
                        seq_node->val = SCStrdup(value);
                        if (unlikely(seq_node->val == NULL)) {
                            SCFree(seq_node->name);
                            goto fail;
                        }
                    } else {
                        seq_node->val = NULL;
                    }
                }
                TAILQ_INSERT_TAIL(&parent->head, seq_node, next);
            }
            else {
                if (state == CONF_INCLUDE) {
                    SCLogInfo("Including configuration file %s.", value);
                    if (ConfYamlHandleInclude(parent, value) != 0) {
                        goto fail;
                    }
                    state = CONF_KEY;
                }
                else if (state == CONF_KEY) {

                    if (strcmp(value, "include") == 0) {
                        state = CONF_INCLUDE;
                        if (++include_count > 1) {
                            SCLogWarning("Multipline \"include\" fields at the same level are "
                                         "deprecated and will not work in Suricata 8, please move "
                                         "to an array of include files: line: %zu",
                                    parser->mark.line);
                        }
                        goto next;
                    }

                    if (parent->is_seq) {
                        if (parent->val == NULL) {
                            parent->val = SCStrdup(value);
                            if (parent->val && strchr(parent->val, '_'))
                                Mangle(parent->val);
                        }
                    }

                    if (strchr(value, '.') != NULL) {
                        node = ConfNodeGetNodeOrCreate(parent, value, 0);
                        if (node == NULL) {
                            /* Error message already logged. */
                            goto fail;
                        }
                    } else {
                        ConfNode *existing = ConfNodeLookupChild(parent, value);
                        if (existing != NULL) {
                            if (!existing->final) {
                                SCLogInfo("Configuration node '%s' redefined.", existing->name);
                                ConfNodePrune(existing);
                            }
                            node = existing;
                        } else {
                            node = ConfNodeNew();
                            if (unlikely(node == NULL)) {
                                goto fail;
                            }
                            node->name = SCStrdup(value);
                            node->parent = parent;
                            if (node->name && strchr(node->name, '_')) {
                                if (!(parent->name &&
                                            ((strcmp(parent->name, "address-groups") == 0) ||
                                                    (strcmp(parent->name, "port-groups") == 0)))) {
                                    Mangle(node->name);
                                    if (mangle_errors < MANGLE_ERRORS_MAX) {
                                        SCLogWarning(
                                                "%s is deprecated. Please use %s on line %" PRIuMAX
                                                ".",
                                                value, node->name,
                                                (uintmax_t)parser->mark.line + 1);
                                        mangle_errors++;
                                        if (mangle_errors >= MANGLE_ERRORS_MAX)
                                            SCLogWarning("not showing more "
                                                         "parameter name warnings.");
                                    }
                                }
                            }
                            TAILQ_INSERT_TAIL(&parent->head, node, next);
                        }
                    }
                    state = CONF_VAL;
                }
                else {
                    if (value != NULL && (tag != NULL) && (strcmp(tag, "!include") == 0)) {
                        SCLogInfo("Including configuration file %s at "
                            "parent node %s.", value, node->name);
                        if (ConfYamlHandleInclude(node, value) != 0)
                            goto fail;
                    } else if (!node->final && value != NULL) {
                        if (node->val != NULL)
                            SCFree(node->val);
                        node->val = SCStrdup(value);
                    }
                    state = CONF_KEY;
                }
            }
        }
        else if (event.type == YAML_SEQUENCE_START_EVENT) {
            SCLogDebug("event.type=YAML_SEQUENCE_START_EVENT; state=%d", state);
            /* If we're processing a list of includes, use the current parent. */
            if (ConfYamlParse(parser, state == CONF_INCLUDE ? parent : node, 1, rlevel,
                        state == CONF_INCLUDE ? CONF_INCLUDE : 0) != 0)
                goto fail;
            node->is_seq = 1;
            state = CONF_KEY;
        }
        else if (event.type == YAML_SEQUENCE_END_EVENT) {
            SCLogDebug("event.type=YAML_SEQUENCE_END_EVENT; state=%d", state);
            done = 1;
        }
        else if (event.type == YAML_MAPPING_START_EVENT) {
            SCLogDebug("event.type=YAML_MAPPING_START_EVENT; state=%d", state);
            if (state == CONF_INCLUDE) {
                SCLogError("Include fields cannot be a mapping: line %zu", parser->mark.line);
                goto fail;
            }
            if (inseq) {
                char sequence_node_name[DEFAULT_NAME_LEN];
                snprintf(sequence_node_name, DEFAULT_NAME_LEN, "%d", seq_idx++);
                ConfNode *seq_node = NULL;
                if (was_empty < 0) {
                    // initialize was_empty
                    if (TAILQ_EMPTY(&node->head)) {
                        was_empty = 1;
                    } else {
                        was_empty = 0;
                    }
                }
                // we only check if the node's list was not empty at first
                if (was_empty == 0) {
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
                    // do not fuzz quadratic-complexity overlong sequence of scalars
                    if (seq_idx > 256) {
                        goto fail;
                    }
#endif
                    seq_node = ConfNodeLookupChild(node, sequence_node_name);
                }
                if (seq_node != NULL) {
                    /* The sequence node has already been set, probably
                     * from the command line.  Remove it so it gets
                     * re-added in the expected order for iteration.
                     */
                    TAILQ_REMOVE(&node->head, seq_node, next);
                }
                else {
                    seq_node = ConfNodeNew();
                    if (unlikely(seq_node == NULL)) {
                        goto fail;
                    }
                    seq_node->name = SCStrdup(sequence_node_name);
                    if (unlikely(seq_node->name == NULL)) {
                        SCFree(seq_node);
                        goto fail;
                    }
                }
                seq_node->is_seq = 1;
                TAILQ_INSERT_TAIL(&node->head, seq_node, next);
                if (ConfYamlParse(parser, seq_node, 0, rlevel, 0) != 0)
                    goto fail;
            }
            else {
                if (ConfYamlParse(parser, node, inseq, rlevel, 0) != 0)
                    goto fail;
            }
            state = CONF_KEY;
        }
        else if (event.type == YAML_MAPPING_END_EVENT) {
            SCLogDebug("event.type=YAML_MAPPING_END_EVENT; state=%d", state);
            done = 1;
        }
        else if (event.type == YAML_STREAM_END_EVENT) {
            SCLogDebug("event.type=YAML_STREAM_END_EVENT; state=%d", state);
            done = 1;
        }

    next:
        yaml_event_delete(&event);
        continue;

    fail:
        yaml_event_delete(&event);
        retval = -1;
        break;
    }

    rlevel--;
    return retval;
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
int
ConfYamlLoadFile(const char *filename)
{
    FILE *infile;
    yaml_parser_t parser;
    int ret;
    ConfNode *root = ConfGetRootNode();

    if (yaml_parser_initialize(&parser) != 1) {
        SCLogError("failed to initialize yaml parser.");
        return -1;
    }

    struct stat stat_buf;
    if (stat(filename, &stat_buf) == 0) {
        if (stat_buf.st_mode & S_IFDIR) {
            SCLogError("yaml argument is not a file but a directory: %s. "
                       "Please specify the yaml file in your -c option.",
                    filename);
            yaml_parser_delete(&parser);
            return -1;
        }
    }

    // coverity[toctou : FALSE]
    infile = fopen(filename, "r");
    if (infile == NULL) {
        SCLogError("failed to open file: %s: %s", filename, strerror(errno));
        yaml_parser_delete(&parser);
        return -1;
    }

    if (conf_dirname == NULL) {
        ConfYamlSetConfDirname(filename);
    }

    yaml_parser_set_input_file(&parser, infile);
    ret = ConfYamlParse(&parser, root, 0, 0, 0);
    yaml_parser_delete(&parser);
    fclose(infile);

    return ret;
}

/**
 * \brief Load configuration from a YAML string.
 */
int
ConfYamlLoadString(const char *string, size_t len)
{
    ConfNode *root = ConfGetRootNode();
    yaml_parser_t parser;
    int ret;

    if (yaml_parser_initialize(&parser) != 1) {
        fprintf(stderr, "Failed to initialize yaml parser.\n");
        exit(EXIT_FAILURE);
    }
    yaml_parser_set_input_string(&parser, (const unsigned char *)string, len);
    ret = ConfYamlParse(&parser, root, 0, 0, 0);
    yaml_parser_delete(&parser);

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
 * \param prefix Name prefix to use.
 *
 * \retval 0 on success, -1 on failure.
 */
int
ConfYamlLoadFileWithPrefix(const char *filename, const char *prefix)
{
    FILE *infile;
    yaml_parser_t parser;
    int ret;
    ConfNode *root = ConfGetNode(prefix);

    struct stat stat_buf;
    /* coverity[toctou] */
    if (stat(filename, &stat_buf) == 0) {
        if (stat_buf.st_mode & S_IFDIR) {
            SCLogError("yaml argument is not a file but a directory: %s. "
                       "Please specify the yaml file in your -c option.",
                    filename);
            return -1;
        }
    }

    if (yaml_parser_initialize(&parser) != 1) {
        SCLogError("failed to initialize yaml parser.");
        return -1;
    }

    /* coverity[toctou] */
    infile = fopen(filename, "r");
    if (infile == NULL) {
        SCLogError("failed to open file: %s: %s", filename, strerror(errno));
        yaml_parser_delete(&parser);
        return -1;
    }

    if (conf_dirname == NULL) {
        ConfYamlSetConfDirname(filename);
    }

    if (root == NULL) {
        /* if node at 'prefix' doesn't yet exist, add a place holder */
        ConfSet(prefix, "<prefix root node>");
        root = ConfGetNode(prefix);
        if (root == NULL) {
            fclose(infile);
            yaml_parser_delete(&parser);
            return -1;
        }
    }
    yaml_parser_set_input_file(&parser, infile);
    ret = ConfYamlParse(&parser, root, 0, 0, 0);
    yaml_parser_delete(&parser);
    fclose(infile);

    return ret;
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

    ConfCreateContextBackup();
    ConfInit();

    ConfYamlLoadString(input, strlen(input));

    ConfNode *node;
    node = ConfGetNode("rule-files");
    FAIL_IF_NULL(node);
    FAIL_IF_NOT(ConfNodeIsSequence(node));
    FAIL_IF(TAILQ_EMPTY(&node->head));
    int i = 0;
    ConfNode *filename;
    TAILQ_FOREACH(filename, &node->head, next) {
        if (i == 0) {
            FAIL_IF(strcmp(filename->val, "netbios.rules") != 0);
            FAIL_IF(ConfNodeIsSequence(filename));
            FAIL_IF(filename->is_seq != 0);
        }
        else if (i == 1) {
            FAIL_IF(strcmp(filename->val, "x11.rules") != 0);
            FAIL_IF(ConfNodeIsSequence(filename));
        }
        FAIL_IF(i > 1);
        i++;
    }

    ConfDeInit();
    ConfRestoreContextBackup();
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

    ConfCreateContextBackup();
    ConfInit();

    ConfYamlLoadString(input, strlen(input));

    ConfNode *outputs;
    outputs = ConfGetNode("logging.output");
    FAIL_IF_NULL(outputs);

    ConfNode *output;
    ConfNode *output_param;

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

    ConfDeInit();
    ConfRestoreContextBackup();

    PASS;
}

/**
 * Try to load something that is not a valid YAML file.
 */
static int
ConfYamlNonYamlFileTest(void)
{
    ConfCreateContextBackup();
    ConfInit();

    FAIL_IF(ConfYamlLoadFile("/etc/passwd") != -1);

    ConfDeInit();
    ConfRestoreContextBackup();

    PASS;
}

static int
ConfYamlBadYamlVersionTest(void)
{
    char input[] = "\
%YAML 9.9\n\
---\n\
logging:\n\
  output:\n\
    - interface: console\n\
      log-level: error\n\
    - interface: syslog\n\
      facility: local4\n\
      log-level: info\n\
";

    ConfCreateContextBackup();
    ConfInit();

    FAIL_IF(ConfYamlLoadString(input, strlen(input)) != -1);

    ConfDeInit();
    ConfRestoreContextBackup();

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

    ConfCreateContextBackup();
    ConfInit();

    FAIL_IF(ConfYamlLoadString(input, strlen(input)) != 0);

    ConfNode *outputs;
    outputs = ConfGetNode("libhtp.server-config");
    FAIL_IF_NULL(outputs);

    ConfNode *node;

    node = TAILQ_FIRST(&outputs->head);
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->name, "0") != 0);

    node = TAILQ_FIRST(&node->head);
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->name, "apache-php") != 0);

    node = ConfNodeLookupChild(node, "address");
    FAIL_IF_NULL(node);

    node = TAILQ_FIRST(&node->head);
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->name, "0") != 0);
    FAIL_IF(strcmp(node->val, "192.168.1.0/24") != 0);

    ConfDeInit();
    ConfRestoreContextBackup();

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

    ConfCreateContextBackup();
    ConfInit();

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

    FAIL_IF(ConfYamlLoadFile("ConfYamlFileIncludeTest-config.yaml") != 0);

    /* Check values that should have been loaded into the root of the
     * configuration. */
    ConfNode *node;
    node = ConfGetNode("host-mode");
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->val, "auto") != 0);

    node = ConfGetNode("unix-command.enabled");
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->val, "no") != 0);

    /* Check for values that were included under a mapping. */
    node = ConfGetNode("mapping.host-mode");
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->val, "auto") != 0);

    node = ConfGetNode("mapping.unix-command.enabled");
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->val, "no") != 0);

    ConfDeInit();
    ConfRestoreContextBackup();

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

    ConfCreateContextBackup();
    ConfInit();

    FAIL_IF(ConfYamlLoadString(config, strlen(config)) != 0);
    FAIL_IF_NOT(ConfGet("some-log-dir", &value));
    FAIL_IF(strcmp(value, "/tmp") != 0);

    /* Test that parent.child0 does not exist, but child1 does. */
    FAIL_IF_NOT_NULL(ConfGetNode("parent.child0"));
    FAIL_IF_NOT(ConfGet("parent.child1.key", &value));
    FAIL_IF(strcmp(value, "value") != 0);

    /* First check that vars.address-groups.EXTERNAL_NET has the
     * expected parent of vars.address-groups and save this
     * pointer. We want to make sure that the overrided value has the
     * same parent later on. */
    ConfNode *vars_address_groups = ConfGetNode("vars.address-groups");
    FAIL_IF_NULL(vars_address_groups);
    ConfNode *vars_address_groups_external_net = ConfGetNode("vars.address-groups.EXTERNAL_NET");
    FAIL_IF_NULL(vars_address_groups_external_net);
    FAIL_IF_NOT(vars_address_groups_external_net->parent == vars_address_groups);

    /* Now check that HOME_NET has the overrided value. */
    ConfNode *vars_address_groups_home_net = ConfGetNode("vars.address-groups.HOME_NET");
    FAIL_IF_NULL(vars_address_groups_home_net);
    FAIL_IF(strcmp(vars_address_groups_home_net->val, "10.10.10.10/32") != 0);

    /* And check that it has the correct parent. */
    FAIL_IF_NOT(vars_address_groups_home_net->parent == vars_address_groups);

    ConfDeInit();
    ConfRestoreContextBackup();

    PASS;
}

/**
 * Test that a configuration parameter loaded from YAML doesn't
 * override a 'final' value that may be set on the command line.
 */
static int
ConfYamlOverrideFinalTest(void)
{
    ConfCreateContextBackup();
    ConfInit();

    char config[] =
        "%YAML 1.1\n"
        "---\n"
        "default-log-dir: /var/log\n";

    /* Set the log directory as if it was set on the command line. */
    FAIL_IF_NOT(ConfSetFinal("default-log-dir", "/tmp"));
    FAIL_IF(ConfYamlLoadString(config, strlen(config)) != 0);

    const char *default_log_dir;

    FAIL_IF_NOT(ConfGet("default-log-dir", &default_log_dir));
    FAIL_IF(strcmp(default_log_dir, "/tmp") != 0);

    ConfDeInit();
    ConfRestoreContextBackup();

    PASS;
}

static int ConfYamlNull(void)
{
    ConfCreateContextBackup();
    ConfInit();

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
    FAIL_IF(ConfYamlLoadString(config, strlen(config)) != 0);

    const char *val;

    FAIL_IF_NOT(ConfGet("quoted-tilde", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(ConfGet("unquoted-tilde", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(ConfGet("quoted-null", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(ConfGet("unquoted-null", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(ConfGet("quoted-Null", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(ConfGet("unquoted-Null", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(ConfGet("quoted-NULL", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(ConfGet("unquoted-NULL", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(ConfGet("empty-quoted", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(ConfGet("empty-unquoted", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(ConfGet("list.0", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(ConfGet("list.1", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(ConfGet("list.2", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(ConfGet("list.3", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(ConfGet("list.4", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(ConfGet("list.5", &val));
    FAIL_IF_NOT_NULL(val);

    FAIL_IF_NOT(ConfGet("list.6", &val));
    FAIL_IF_NULL(val);
    FAIL_IF_NOT(ConfGet("list.7", &val));
    FAIL_IF_NOT_NULL(val);

    ConfDeInit();
    ConfRestoreContextBackup();

    PASS;
}

#endif /* UNITTESTS */

void
ConfYamlRegisterTests(void)
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
#endif /* UNITTESTS */
}
