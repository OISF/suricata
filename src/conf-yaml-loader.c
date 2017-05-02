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
 * \author Endace Technology Limited - Jason Ish <jason.ish@endace.com>
 *
 * YAML configuration loader.
 */

#include <yaml.h>
#include "suricata-common.h"
#include "conf.h"
#include "conf-yaml-loader.h"
#include "util-path.h"
#include "util-debug.h"
#include "util-unittest.h"

#define YAML_VERSION_MAJOR 1
#define YAML_VERSION_MINOR 1

/* Sometimes we'll have to create a node name on the fly (integer
 * conversion, etc), so this is a default length to allocate that will
 * work most of the time. */
#define DEFAULT_NAME_LEN 16

#define MANGLE_ERRORS_MAX 10
static int mangle_errors = 0;

static char *conf_dirname = NULL;

static int ConfYamlParse(yaml_parser_t *parser, ConfNode *parent, int inseq);

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
            SCLogError(SC_ERR_MEM_ALLOC,
               "ERROR: Failed to allocate memory while loading configuration.");
            exit(EXIT_FAILURE);
        }
    }
    else {
        conf_dirname = SCStrdup(filename);
        if (conf_dirname == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC,
               "ERROR: Failed to allocate memory while loading configuration.");
            exit(EXIT_FAILURE);
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
static int
ConfYamlHandleInclude(ConfNode *parent, const char *filename)
{
    yaml_parser_t parser;
    char include_filename[PATH_MAX];
    FILE *file;

    if (yaml_parser_initialize(&parser) != 1) {
        SCLogError(SC_ERR_CONF_YAML_ERROR, "Failed to initialize YAML parser");
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
        SCLogError(SC_ERR_FOPEN,
            "Failed to open configuration include file %s: %s",
            include_filename, strerror(errno));
        return -1;
    }

    yaml_parser_set_input_file(&parser, file);

    if (ConfYamlParse(&parser, parent, 0) != 0) {
        SCLogError(SC_ERR_CONF_YAML_ERROR,
            "Failed to include configuration file %s", filename);
        return -1;
    }

    yaml_parser_delete(&parser);
    fclose(file);

    return 0;
}

/**
 * \brief Parse a YAML layer.
 *
 * \param parser A pointer to an active yaml_parser_t.
 * \param parent The parent configuration node.
 *
 * \retval 0 on success, -1 on failure.
 */
static int
ConfYamlParse(yaml_parser_t *parser, ConfNode *parent, int inseq)
{
    ConfNode *node = parent;
    yaml_event_t event;
    memset(&event, 0, sizeof(event));
    int done = 0;
    int state = 0;
    int seq_idx = 0;

    while (!done) {
        if (!yaml_parser_parse(parser, &event)) {
            SCLogError(SC_ERR_CONF_YAML_ERROR,
                "Failed to parse configuration file at line %" PRIuMAX ": %s\n",
                (uintmax_t)parser->problem_mark.line, parser->problem);
            return -1;
        }

        if (event.type == YAML_DOCUMENT_START_EVENT) {
            SCLogDebug("event.type=YAML_DOCUMENT_START_EVENT; state=%d", state);
            /* Verify YAML version - its more likely to be a valid
             * Suricata configuration file if the version is
             * correct. */
            yaml_version_directive_t *ver =
                event.data.document_start.version_directive;
            if (ver == NULL) {
                fprintf(stderr, "ERROR: Invalid configuration file.\n\n");
                fprintf(stderr, "The configuration file must begin with the following two lines:\n\n");
                fprintf(stderr, "%%YAML 1.1\n---\n\n");
                goto fail;
            }
            int major = ver->major;
            int minor = ver->minor;
            if (!(major == YAML_VERSION_MAJOR && minor == YAML_VERSION_MINOR)) {
                fprintf(stderr, "ERROR: Invalid YAML version.  Must be 1.1\n");
                goto fail;
            }
        }
        else if (event.type == YAML_SCALAR_EVENT) {
            char *value = (char *)event.data.scalar.value;
            char *tag = (char *)event.data.scalar.tag;
            SCLogDebug("event.type=YAML_SCALAR_EVENT; state=%d; value=%s; "
                "tag=%s; inseq=%d", state, value, tag, inseq);
            if (inseq) {
                char sequence_node_name[DEFAULT_NAME_LEN];
                snprintf(sequence_node_name, DEFAULT_NAME_LEN, "%d", seq_idx++);
                ConfNode *seq_node = ConfNodeLookupChild(parent,
                    sequence_node_name);
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
                        return -1;
                    }
                    seq_node->name = SCStrdup(sequence_node_name);
                    if (unlikely(seq_node->name == NULL)) {
                        SCFree(seq_node);
                        return -1;
                    }
                    seq_node->val = SCStrdup(value);
                    if (unlikely(seq_node->val == NULL)) {
                        SCFree(seq_node->name);
                        return -1;
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
                        goto next;
                    }

                    if (parent->is_seq) {
                        if (parent->val == NULL) {
                            parent->val = SCStrdup(value);
                            if (parent->val && strchr(parent->val, '_'))
                                Mangle(parent->val);
                        }
                    }
                    ConfNode *existing = ConfNodeLookupChild(parent, value);
                    if (existing != NULL) {
                        if (!existing->final) {
                            SCLogInfo("Configuration node '%s' redefined.",
                                existing->name);
                            ConfNodePrune(existing);
                        }
                        node = existing;
                    }
                    else {
                        node = ConfNodeNew();
                        node->name = SCStrdup(value);
                        if (node->name && strchr(node->name, '_')) {
                            if (!(parent->name &&
                                   ((strcmp(parent->name, "address-groups") == 0) ||
                                    (strcmp(parent->name, "port-groups") == 0)))) {
                                Mangle(node->name);
                                if (mangle_errors < MANGLE_ERRORS_MAX) {
                                    SCLogWarning(SC_WARN_DEPRECATED,
                                            "%s is deprecated. Please use %s on line %"PRIuMAX".",
                                            value, node->name, (uintmax_t)parser->mark.line+1);
                                    mangle_errors++;
                                    if (mangle_errors >= MANGLE_ERRORS_MAX)
                                        SCLogWarning(SC_WARN_DEPRECATED, "not showing more "
                                                "parameter name warnings.");
                                }
                            }
                        }
                        TAILQ_INSERT_TAIL(&parent->head, node, next);
                    }
                    state = CONF_VAL;
                }
                else {
                    if ((tag != NULL) && (strcmp(tag, "!include") == 0)) {
                        SCLogInfo("Including configuration file %s at "
                            "parent node %s.", value, node->name);
                        if (ConfYamlHandleInclude(node, value) != 0)
                            goto fail;
                    }
                    else if (!node->final) {
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
            if (ConfYamlParse(parser, node, 1) != 0)
                goto fail;
            node->is_seq = 1;
            state = CONF_KEY;
        }
        else if (event.type == YAML_SEQUENCE_END_EVENT) {
            SCLogDebug("event.type=YAML_SEQUENCE_END_EVENT; state=%d", state);
            return 0;
        }
        else if (event.type == YAML_MAPPING_START_EVENT) {
            SCLogDebug("event.type=YAML_MAPPING_START_EVENT; state=%d", state);
            if (inseq) {
                char sequence_node_name[DEFAULT_NAME_LEN];
                snprintf(sequence_node_name, DEFAULT_NAME_LEN, "%d", seq_idx++);
                ConfNode *seq_node = ConfNodeLookupChild(node,
                    sequence_node_name);
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
                        return -1;
                    }
                    seq_node->name = SCStrdup(sequence_node_name);
                    if (unlikely(seq_node->name == NULL)) {
                        SCFree(seq_node);
                        return -1;
                    }
                }
                seq_node->is_seq = 1;
                TAILQ_INSERT_TAIL(&node->head, seq_node, next);
                if (ConfYamlParse(parser, seq_node, 0) != 0)
                    goto fail;
            }
            else {
                if (ConfYamlParse(parser, node, inseq) != 0)
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
        return -1;
    }

    return 0;
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
        SCLogError(SC_ERR_FATAL, "failed to initialize yaml parser.");
        return -1;
    }

    struct stat stat_buf;
    if (stat(filename, &stat_buf) == 0) {
        if (stat_buf.st_mode & S_IFDIR) {
            SCLogError(SC_ERR_FATAL, "yaml argument is not a file but a directory: %s. "
                    "Please specify the yaml file in your -c option.", filename);
            return -1;
        }
    }

    infile = fopen(filename, "r");
    if (infile == NULL) {
        SCLogError(SC_ERR_FATAL, "failed to open file: %s: %s", filename,
            strerror(errno));
        yaml_parser_delete(&parser);
        return -1;
    }

    if (conf_dirname == NULL) {
        ConfYamlSetConfDirname(filename);
    }

    yaml_parser_set_input_file(&parser, infile);
    ret = ConfYamlParse(&parser, root, 0);
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
    ret = ConfYamlParse(&parser, root, 0);
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

    if (yaml_parser_initialize(&parser) != 1) {
        SCLogError(SC_ERR_FATAL, "failed to initialize yaml parser.");
        return -1;
    }

    struct stat stat_buf;
    /* coverity[toctou] */
    if (stat(filename, &stat_buf) == 0) {
        if (stat_buf.st_mode & S_IFDIR) {
            SCLogError(SC_ERR_FATAL, "yaml argument is not a file but a directory: %s. "
                    "Please specify the yaml file in your -c option.", filename);
            return -1;
        }
    }

    /* coverity[toctou] */
    infile = fopen(filename, "r");
    if (infile == NULL) {
        SCLogError(SC_ERR_FATAL, "failed to open file: %s: %s", filename,
            strerror(errno));
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
    ret = ConfYamlParse(&parser, root, 0);
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
    if (node == NULL)
        return 0;
    if (!ConfNodeIsSequence(node))
        return 0;
    if (TAILQ_EMPTY(&node->head))
        return 0;
    int i = 0;
    ConfNode *filename;
    TAILQ_FOREACH(filename, &node->head, next) {
        if (i == 0) {
            if (strcmp(filename->val, "netbios.rules") != 0)
                return 0;
            if (ConfNodeIsSequence(filename))
                return 0;
            if (filename->is_seq != 0)
                return 0;
        }
        else if (i == 1) {
            if (strcmp(filename->val, "x11.rules") != 0)
                return 0;
            if (ConfNodeIsSequence(filename))
                return 0;
        }
        else {
            return 0;
        }
        i++;
    }

    ConfDeInit();
    ConfRestoreContextBackup();

    return 1;
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
    if (outputs == NULL)
        return 0;

    ConfNode *output;
    ConfNode *output_param;

    output = TAILQ_FIRST(&outputs->head);
    if (output == NULL)
        return 0;
    if (strcmp(output->name, "0") != 0)
        return 0;
    output_param = TAILQ_FIRST(&output->head);
    if (output_param == NULL)
        return 0;
    if (strcmp(output_param->name, "interface") != 0)
        return 0;
    if (strcmp(output_param->val, "console") != 0)
        return 0;
    output_param = TAILQ_NEXT(output_param, next);
    if (strcmp(output_param->name, "log-level") != 0)
        return 0;
    if (strcmp(output_param->val, "error") != 0)
        return 0;

    output = TAILQ_NEXT(output, next);
    if (output == NULL)
        return 0;
    if (strcmp(output->name, "1") != 0)
        return 0;
    output_param = TAILQ_FIRST(&output->head);
    if (output_param == NULL)
        return 0;
    if (strcmp(output_param->name, "interface") != 0)
        return 0;
    if (strcmp(output_param->val, "syslog") != 0)
        return 0;
    output_param = TAILQ_NEXT(output_param, next);
    if (strcmp(output_param->name, "facility") != 0)
        return 0;
    if (strcmp(output_param->val, "local4") != 0)
        return 0;
    output_param = TAILQ_NEXT(output_param, next);
    if (strcmp(output_param->name, "log-level") != 0)
        return 0;
    if (strcmp(output_param->val, "info") != 0)
        return 0;

    ConfDeInit();
    ConfRestoreContextBackup();

    return 1;
}

/**
 * Try to load something that is not a valid YAML file.
 */
static int
ConfYamlNonYamlFileTest(void)
{
    ConfCreateContextBackup();
    ConfInit();

    if (ConfYamlLoadFile("/etc/passwd") != -1)
        return 0;

    ConfDeInit();
    ConfRestoreContextBackup();

    return 1;
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

    if (ConfYamlLoadString(input, strlen(input)) != -1)
        return 0;

    ConfDeInit();
    ConfRestoreContextBackup();

    return 1;
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

    if (ConfYamlLoadString(input, strlen(input)) != 0)
        return 0;

    ConfNode *outputs;
    outputs = ConfGetNode("libhtp.server-config");
    if (outputs == NULL)
        return 0;

    ConfNode *node;

    node = TAILQ_FIRST(&outputs->head);
    if (node == NULL)
        return 0;
    if (strcmp(node->name, "0") != 0)
        return 0;
    node = TAILQ_FIRST(&node->head);
    if (node == NULL)
        return 0;
    if (strcmp(node->name, "apache-php") != 0)
        return 0;

    node = ConfNodeLookupChild(node, "address");
    if (node == NULL)
        return 0;
    node = TAILQ_FIRST(&node->head);
    if (node == NULL)
        return 0;
    if (strcmp(node->name, "0") != 0)
        return 0;
    if (strcmp(node->val, "192.168.1.0/24") != 0)
        return 0;

    ConfDeInit();
    ConfRestoreContextBackup();

    return 1;
}

/**
 * Test file inclusion support.
 */
static int
ConfYamlFileIncludeTest(void)
{
    int ret = 0;
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
    if ((config_file = fopen(config_filename, "w")) == NULL) {
        goto cleanup;
    }
    if (fwrite(config_file_contents, strlen(config_file_contents), 1,
            config_file) != 1) {
        goto cleanup;
    }
    fclose(config_file);
    if ((config_file = fopen(include_filename, "w")) == NULL) {
        goto cleanup;
    }
    if (fwrite(include_file_contents, strlen(include_file_contents), 1,
            config_file) != 1) {
        goto cleanup;
    }
    fclose(config_file);

    /* Reset conf_dirname. */
    if (conf_dirname != NULL) {
        SCFree(conf_dirname);
        conf_dirname = NULL;
    }

    if (ConfYamlLoadFile("ConfYamlFileIncludeTest-config.yaml") != 0)
        goto cleanup;

    /* Check values that should have been loaded into the root of the
     * configuration. */
    ConfNode *node;
    node = ConfGetNode("host-mode");
    if (node == NULL)
        goto cleanup;
    if (strcmp(node->val, "auto") != 0)
        goto cleanup;
    node = ConfGetNode("unix-command.enabled");
    if (node == NULL)
        goto cleanup;
    if (strcmp(node->val, "no") != 0)
        goto cleanup;

    /* Check for values that were included under a mapping. */
    node = ConfGetNode("mapping.host-mode");
    if (node == NULL)
        goto cleanup;
    if (strcmp(node->val, "auto") != 0)
        goto cleanup;
    node = ConfGetNode("mapping.unix-command.enabled");
    if (node == NULL)
        goto cleanup;
    if (strcmp(node->val, "no") != 0)
        goto cleanup;

    ConfDeInit();
    ConfRestoreContextBackup();

    ret = 1;

cleanup:
    unlink(config_filename);
    unlink(include_filename);

    return ret;
}

/**
 * Test that a configuration section is overridden but subsequent
 * occurrences.
 */
static int
ConfYamlOverrideTest(void)
{
    char config[] =
        "%YAML 1.1\n"
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
        ;
    const char *value;

    ConfCreateContextBackup();
    ConfInit();

    if (ConfYamlLoadString(config, strlen(config)) != 0)
        return 0;
    if (!ConfGet("some-log-dir", &value))
        return 0;
    if (strcmp(value, "/tmp") != 0)
        return 0;

    /* Test that parent.child0 does not exist, but child1 does. */
    if (ConfGetNode("parent.child0") != NULL)
        return 0;
    if (!ConfGet("parent.child1.key", &value))
        return 0;
    if (strcmp(value, "value") != 0)
        return 0;

    ConfDeInit();
    ConfRestoreContextBackup();

    return 1;
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
    if (!ConfSetFinal("default-log-dir", "/tmp"))
        return 0;
    if (ConfYamlLoadString(config, strlen(config)) != 0)
        return 0;

    const char *default_log_dir;

    if (!ConfGet("default-log-dir", &default_log_dir))
        return 0;
    if (strcmp(default_log_dir, "/tmp") != 0) {
        fprintf(stderr, "final value was reassigned\n");
        return 0;
    }

    ConfDeInit();
    ConfRestoreContextBackup();

    return 1;
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
#endif /* UNITTESTS */
}
