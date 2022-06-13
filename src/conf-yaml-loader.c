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

#include "suricata-common.h"
#include "conf.h"
#include "conf-yaml-loader.h"
#include "util-path.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "rust.h"
#include "rust-config.h"

/* Sometimes we'll have to create a node name on the fly (integer
 * conversion, etc), so this is a default length to allocate that will
 * work most of the time. */
#define DEFAULT_NAME_LEN 16

#define MANGLE_ERRORS_MAX 10
static int mangle_errors = 0;

/**
 * \brief Mangle unsupported characters.
 *
 * \param string A pointer to an null terminated string.
 *
 * \retval none
 */
static bool Mangle(char *string)
{
    bool mangled = false;
    char *c;

    while ((c = strchr(string, '_'))) {
        mangled = true;
        *c = '-';
    }

    return mangled;
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
    char errbuf[SURI_CONFIG_ERRBUF_SIZE];
    Yaml *yaml = SuriConfigLoadFromFile(filename, errbuf);
    if (yaml == NULL) {
        SCLogError(SC_ERR_FATAL, "Failed to load %s: %s", filename, errbuf);
        return -1;
    }
    ConfNode *root = ConfGetRootNode();
    ConfNodeFromYaml(yaml, root, false);
    SuriConfigYamlFree(yaml);
    return 0;
}

/**
 * \brief Load configuration from a YAML string.
 */
int
ConfYamlLoadString(const char *string, size_t len)
{
    const char *errbuf;
    ConfNode *root = ConfGetRootNode();
    Yaml *yaml = SuriConfigLoadFromString(string, &errbuf);
    if (yaml == NULL) {
        SCLogError(SC_ERR_CONF_YAML_ERROR, "Failed to load YAML from string: %s", errbuf);
        return -1;
    }
    ConfNodeFromYaml(yaml, root, false);
    SuriConfigYamlFree(yaml);
    return 0;
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
    ConfNode *root = ConfGetNode(prefix);
    if (root == NULL) {
        /* if node at 'prefix' doesn't yet exist, add a place holder */
        ConfSet(prefix, "<prefix root node>");
        root = ConfGetNode(prefix);
        if (root == NULL) {
            return -1;
        }
    }

    char errbuf[SURI_CONFIG_ERRBUF_SIZE];
    Yaml *yaml = SuriConfigLoadFromFile(filename, errbuf);
    if (yaml == NULL) {
        SCLogError(SC_ERR_FATAL, "Failed to load %s at prefix %s: %s", filename, prefix, errbuf);
        return -1;
    }
    ConfNodeFromYaml(yaml, root, false);
    SuriConfigYamlFree(yaml);

    return 0;
}

void ConfNodeFromYaml(Yaml *yaml, ConfNode *node, bool in_vars)
{
    switch (SuriConfigYamlGetType(yaml)) {
        case SURI_CONFIG_YAML_TYPE_NULL:
            // Do nothing, leaves value as null.
            break;
        case SURI_CONFIG_YAML_TYPE_BOOLEAN:
        case SURI_CONFIG_YAML_TYPE_INTEGER:
        case SURI_CONFIG_YAML_TYPE_REAL:
        case SURI_CONFIG_YAML_TYPE_STRING: {
            const char *value = SuriConfigValueString(yaml);
            if (value != NULL) {
                if ((node->val = SCStrdup(value)) == NULL) {
                    return;
                }
            }
            break;
        }
        case SURI_CONFIG_YAML_TYPE_HASH: {
            SuriConfigYamlHashIter *iter = SuriConfigHashIter(yaml);
            if (iter == NULL) {
                return;
            }
            const char *key = NULL;
            Yaml *yaml_child = NULL;
            while (SuriConfigHashIterNext(iter, &key, &yaml_child)) {
                /* Legacy compatibility. The old loader will set the value
                 * of a hash node containing a hash, to the key of the
                 * first entry in the hash.
                 *
                 * Parts of the Suricata code that depend on this should
                 * be fixed. */
                if (node->val == NULL) {
                    node->val = SCStrdup(key);
                }
                switch (SuriConfigYamlGetType(yaml_child)) {
                    case SURI_CONFIG_YAML_TYPE_BOOLEAN:
                    case SURI_CONFIG_YAML_TYPE_INTEGER:
                    case SURI_CONFIG_YAML_TYPE_REAL:
                    case SURI_CONFIG_YAML_TYPE_HASH:
                    case SURI_CONFIG_YAML_TYPE_ARRAY:
                    case SURI_CONFIG_YAML_TYPE_NULL:
                    case SURI_CONFIG_YAML_TYPE_STRING: {
                        ConfNode *child = ConfNodeLookupChild(node, key);
                        if (child != NULL) {
                            if (child->val) {
                                continue;
                            }
                        } else {
                            child = ConfNodeNew();
                            if (child == NULL) {
                                return;
                            }
                            if ((child->name = SCStrdup(key)) == NULL) {
                                ConfNodeFree(child);
                                return;
                            }
                            TAILQ_INSERT_TAIL(&node->head, child, next);
                        }
                        if (!in_vars) {
                            if (Mangle(child->name)) {
                                if (mangle_errors < MANGLE_ERRORS_MAX) {
                                    SCLogWarning(SC_WARN_DEPRECATED,
                                            "%s is deprecated. Please use %s.", key, child->name);
                                    mangle_errors++;
                                    if (mangle_errors >= MANGLE_ERRORS_MAX)
                                        SCLogWarning(SC_WARN_DEPRECATED,
                                                "not showing more "
                                                "parameter name warnings.");
                                }
                            }
                        }
                        if (strcmp(key, "vars") == 0) {
                            in_vars = true;
                        }
                        ConfNodeFromYaml(yaml_child, child, in_vars);
                        break;
                    }
                    default:
                        break;
                }
            }
            SuriConfigHashIterFree(iter);
            break;
        }
        case SURI_CONFIG_YAML_TYPE_ARRAY: {
            char sequence_name[5];
            node->is_seq = 1;
            int count = 0;
            Yaml *elem = NULL;
            SuriConfigYamlArrayIter *iter = SuriConfigArrayIter(yaml);
            if (iter == NULL) {
                return;
            }
            while (SuriConfigArrayIterNext(iter, &elem)) {
                snprintf(sequence_name, 4, "%d", count);
                ConfNode *new = ConfNodeNew();
                if (new == NULL) {
                    break;
                }
                if ((new->name = SCStrdup(sequence_name)) == NULL) {
                    ConfNodeFree(new);
                    break;
                }
                ConfNodeFromYaml(elem, new, false);
                TAILQ_INSERT_TAIL(&node->head, new, next);
                count += 1;
            }
            ScConfArrayIterFree(iter);
            break;
        }
        default:
            break;
    }
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
#if 0
    ConfCreateContextBackup();
    ConfInit();

    FAIL_IF(ConfYamlLoadFile("/etc/passwd") != -1);

    ConfDeInit();
    ConfRestoreContextBackup();
#endif
    PASS;
}

static int
ConfYamlBadYamlVersionTest(void)
{
#if 0
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
#endif
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

    FAIL_IF(ConfYamlLoadString(config, strlen(config)) != 0);
    FAIL_IF_NOT(ConfGet("some-log-dir", &value));
    FAIL_IF(strcmp(value, "/tmp") != 0);

    /* Test that parent.child0 does not exist, but child1 does. */
    FAIL_IF_NOT_NULL(ConfGetNode("parent.child0"));
    FAIL_IF_NOT(ConfGet("parent.child1.key", &value));
    FAIL_IF(strcmp(value, "value") != 0);

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

    ConfDump();

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
