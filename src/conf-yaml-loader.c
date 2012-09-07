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
#include <pcre.h>
#include "suricata-common.h"
#include "conf.h"
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

/* Configuration processing states. */
enum conf_state {
    CONF_KEY = 0,
    CONF_VAL,
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
 * \brief Get the compiled pcre for environment variable expansion.
 *
 * \retval The compiled pcre
 */
static pcre *
GetEnvVarPcre(void)
{
    static pcre *envvar_pcre = NULL;
    const char *error;
    int erroroffset;

    static const char pattern[] = "\\$\\{" 
        "("    "[^\\$\\{\\}:-]*" ")"
        "(:-(" "[^\\$\\{\\}:-]*" "))?"
        "\\}";

    if (envvar_pcre == NULL) {
        envvar_pcre = pcre_compile(pattern, 0, &error, &erroroffset, NULL);
        if (envvar_pcre == NULL) {
            fprintf(stderr, "ERROR: Failed to compile pcre: %s", error);
            exit(1);
        }
    }

    return envvar_pcre;
}

/**
 * \brief Perform environment variable expansion on the provided string.
 *
 * \param string The string to perform environment variable expansion.
 *
 * \retval A new string with environment variables expanded, only if expansion
 *    took place.  Otherwise NULL is returned.  As this is a new string it
 *    must be free'd by the caller.
 */
static char *
ExpandEnvVar(char *string)
{
    const char *var_name;
    const char *var_val     = NULL;
    int         var_val_len = 0;
    int         segment_start;
    int         segment_end;
    const char *default_val = NULL;
    char       *new_str;
    int         new_str_len;
    int         ovector[12];

    int match = pcre_exec(GetEnvVarPcre(), NULL, string, strlen(string), 0, 0,
        ovector, 12);
    if (match < 2) {
        return NULL;
    }
    segment_start = ovector[0];
    segment_end = ovector[1];

    if (pcre_get_substring(string, ovector, match, 1, &var_name) < 0) {
        fprintf(stderr, "pcre failure\n");
        exit(1);
    }

    /* Do we also have a default? */
    if (match == 4) {
        if (pcre_get_substring(string, ovector, match, 3, &default_val) < 0) {
            fprintf(stderr, "pcre failure\n");
            exit(1);
        }
    }

    /* Get the environment variable, using the optional default if the
     * environment variable is not set. */
    if (NULL != (var_val = getenv(var_name))) {
        var_val_len = strlen(var_val);
    }
    else if (default_val != NULL) {
        var_val = default_val;
        var_val_len = strlen(var_val);
    }

    /* Calculate the length of the new string including termination
     * and then allocate it. */

    new_str_len = strlen(string) - (segment_end - segment_start) +
        var_val_len + 1;
    BUG_ON(new_str_len < 1);
    new_str = SCCalloc(1, new_str_len);

    /* Build the new string. */
    if (segment_start)
        strncat(new_str, string, segment_start);
    if (var_val != NULL)
        strncat(new_str, var_val, var_val_len);
    if (strlen(string) > (size_t)segment_end)
        strcat(new_str, string + segment_end);

    pcre_free_substring(var_name);
    if (default_val != NULL)
        pcre_free_substring(default_val);

    /* Recurse to expand other variables. */
    char *new_new_str = ExpandEnvVar(new_str);
    if (new_new_str != NULL) {
        SCFree(new_str);
        new_str = new_new_str;
    }

    return new_str;
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
    int done = 0;
    int state = 0;
    int seq_idx = 0;

    while (!done) {
        if (!yaml_parser_parse(parser, &event)) {
            fprintf(stderr,
                "Failed to parse configuration file at line %" PRIuMAX ": %s\n",
                (uintmax_t)parser->problem_mark.line, parser->problem);
            return -1;
        }

        if (event.type == YAML_DOCUMENT_START_EVENT) {
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
            int major = event.data.document_start.version_directive->major;
            int minor = event.data.document_start.version_directive->minor;
            if (!(major == YAML_VERSION_MAJOR && minor == YAML_VERSION_MINOR)) {
                fprintf(stderr, "ERROR: Invalid YAML version.  Must be 1.1\n");
                goto fail;
            }
        }
        else if (event.type == YAML_SCALAR_EVENT) {
            char *value = (char *)event.data.scalar.value;
            SCLogDebug("event.type = YAML_SCALAR_EVENT (%s) inseq=%d",
                value, inseq);
            if (inseq) {
                ConfNode *seq_node = ConfNodeNew();
                seq_node->name = SCCalloc(1, DEFAULT_NAME_LEN);
                if (seq_node->name == NULL)
                    return -1;
                snprintf(seq_node->name, DEFAULT_NAME_LEN, "%d", seq_idx++);
                if (NULL == (seq_node->val = ExpandEnvVar(value))) 
                  seq_node->val = SCStrdup(value);
                TAILQ_INSERT_TAIL(&parent->head, seq_node, next);
            }
            else {
                if (state == CONF_KEY) {
                    if (parent->is_seq) {
                        if (parent->val == NULL) {
                            parent->val = SCStrdup(value);
                            if (parent->val && strchr(parent->val, '_'))
                                Mangle(parent->val);
                        }
                    }
                    ConfNode *n0 = ConfNodeLookupChild(parent, value);
                    if (n0 != NULL) {
                        node = n0;
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
                    if (node->allow_override) {
                        if (node->val != NULL)
                            SCFree(node->val);
                        if (NULL == (node->val = ExpandEnvVar(value))) 
                          node->val = SCStrdup(value);
                    }
                    state = CONF_KEY;
                }
            }
        }
        else if (event.type == YAML_SEQUENCE_START_EVENT) {
            SCLogDebug("event.type = YAML_SEQUENCE_START_EVENT");
            if (ConfYamlParse(parser, node, 1) != 0)
                goto fail;
            state = CONF_KEY;
        }
        else if (event.type == YAML_SEQUENCE_END_EVENT) {
            SCLogDebug("event.type = YAML_SEQUENCE_END_EVENT");
            return 0;
        }
        else if (event.type == YAML_MAPPING_START_EVENT) {
            SCLogDebug("event.type = YAML_MAPPING_START_EVENT");
            if (inseq) {
                ConfNode *seq_node = ConfNodeNew();
                seq_node->is_seq = 1;
                seq_node->name = SCCalloc(1, DEFAULT_NAME_LEN);
                if (seq_node->name == NULL)
                    return -1;
                snprintf(seq_node->name, DEFAULT_NAME_LEN, "%d", seq_idx++);
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
            SCLogDebug("event.type = YAML_MAPPING_END_EVENT");
            done = 1;
        }
        else if (event.type == YAML_STREAM_END_EVENT) {
            done = 1;
        }

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
        fprintf(stderr, "Failed to initialize yaml parser.\n");
        return -1;
    }

    infile = fopen(filename, "r");
    if (infile == NULL) {
        fprintf(stderr, "Failed to open file: %s: %s\n", filename,
            strerror(errno));
        yaml_parser_delete(&parser);
        return -1;
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

#ifdef UNITTESTS

static int
ConfYamlRuleFileTest(void)
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
    if (TAILQ_EMPTY(&node->head))
        return 0;
    int i = 0;
    ConfNode *filename;
    TAILQ_FOREACH(filename, &node->head, next) {
        if (i == 0) {
            if (strcmp(filename->val, "netbios.rules") != 0)
                return 0;
        }
        else if (i == 1) {
            if (strcmp(filename->val, "x11.rules") != 0)
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

static int
ConfYamlEnvVarExpandTest(void)
{
    char *new;
    const char *old_foo = getenv("FOO");
    const char *old_bar = getenv("BAR");

    setenv("FOO", "bar", 1);
    setenv("BAR", "foo", 1);

    if (ExpandEnvVar("something") != NULL)
        return 0;
    if (ExpandEnvVar("$something") != NULL)
        return 0;
    if (ExpandEnvVar("${something") != NULL)
        return 0;

    new = ExpandEnvVar("${}");
    if (new == NULL || strcmp(new, "") != 0) {
        return 0;
    }
    SCFree(new);

    new = ExpandEnvVar("${FOO}");
    if (new == NULL || strcmp(new, "bar") != 0) {
        return 0;
    }
    SCFree(new);

    new = ExpandEnvVar("pre${FOO}");
    if (new == NULL || strcmp(new, "prebar") != 0) {
        return 0;
    }
    SCFree(new);

    new = ExpandEnvVar("${FOO}post");
    if (new == NULL || strcmp(new, "barpost") != 0) {
        fprintf(stderr, "expected '%s', got '%s'\n", "barpost", new);
        return 0;
    }
    SCFree(new);

    new = ExpandEnvVar("pre${FOO}post");
    if (new == NULL || strcmp(new, "prebarpost") != 0) {
        fprintf(stderr, "expected '%s', got '%s'\n", "prebarpost", new);
        return 0;
    }
    SCFree(new);

    new = ExpandEnvVar("pre${NOFOO}post");
    if (new == NULL || strcmp(new, "prepost") != 0) {
        fprintf(stderr, "expected '%s', got '%s'\n", "prepost", new);
        return 0;
    }
    SCFree(new);

    new = ExpandEnvVar("${FOO}${BAR}");
    if (new == NULL || strcmp(new, "barfoo") != 0) {
        fprintf(stderr, "expected '%s', got '%s'\n", "barfoo", new);
        return 0;
    }
    SCFree(new);

    new = ExpandEnvVar("${FOO}${BAR}${FOOBAR}");
    if (new == NULL || strcmp(new, "barfoo") != 0) {
        fprintf(stderr, "expected '%s', got '%s'\n", "barfoo", new);
        return 0;
    }
    SCFree(new);

    new = ExpandEnvVar("${USER}");
    if (new == NULL || strcmp(new, getenv("USER")) != 0) {
        fprintf(stderr, "expected '%s', got '%s'\n", getenv("USER"), new);
        return 0;
    }
    SCFree(new);

    unsetenv("FOO");
    unsetenv("BAR");

    if (old_foo != NULL)
        setenv("FOO", old_foo, 1);
    if (old_bar != NULL)
        setenv("BAR", old_bar, 1);

    return 1;
}

static int
ConfYamlEnvVarExpandTestWithDefaultValue(void)
{
    char *new;

    new = ExpandEnvVar("${FOO:-foo}");
    if (new == NULL || strcmp(new, "foo") != 0) {
        fprintf(stderr, "%d: expected '%s', got '%s'\n", __LINE__, "foo", new);
        return 0;
    }
    SCFree(new);

    new = ExpandEnvVar("pre${FOO:-foo}post");
    if (new == NULL || strcmp(new, "prefoopost") != 0) {
        fprintf(stderr, "%d: expected '%s', got '%s'\n", __LINE__, "foo", new);
        return 0;
    }
    SCFree(new);

    const char *old_foo = getenv("FOO");
    const char *old_bar = getenv("BAR");

    setenv("FOO", "bar", 1);
    setenv("BAR", "foo", 1);

    new = ExpandEnvVar("${FOO:-foo}");
    if (new == NULL || strcmp(new, "bar") != 0) {
        fprintf(stderr, "expected '%s', got '%s'\n", "foo", new);
        return 0;
    }
    SCFree(new);
    
    new = ExpandEnvVar("${FOO:-${BAR}}");
    if (new == NULL || strcmp(new, "bar") != 0) {
        fprintf(stderr, "expected '%s', got '%s'\n", "foo", new);
        return 0;
    }
    SCFree(new);
    
    new = ExpandEnvVar("${NOFOO:-${BAR}}");
    if (new == NULL || strcmp(new, "foo") != 0) {
        fprintf(stderr, "expected '%s', got '%s'\n", "foo", new);
        return 0;
    }
    SCFree(new);

    /* A bit silly now... */
    new = ExpandEnvVar("${NOFOO:-${NOBAR:-nofoobar}}");
    if (new == NULL || strcmp(new, "nofoobar") != 0) {
        fprintf(stderr, "expected '%s', got '%s'\n", "foo", new);
        return 0;
    }
    SCFree(new);

    unsetenv("FOO");
    unsetenv("BAR");

    if (old_foo != NULL)
        setenv("FOO", old_foo, 1);
    if (old_bar != NULL)
        setenv("BAR", old_bar, 1);

    return 1;
}

#endif /* UNITTESTS */

void
ConfYamlRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("ConfYamlRuleFileTest", ConfYamlRuleFileTest, 1);
    UtRegisterTest("ConfYamlLoggingOutputTest", ConfYamlLoggingOutputTest, 1);
    UtRegisterTest("ConfYamlNonYamlFileTest", ConfYamlNonYamlFileTest, 1);
    UtRegisterTest("ConfYamlBadYamlVersionTest", ConfYamlBadYamlVersionTest, 1);
    UtRegisterTest("ConfYamlSecondLevelSequenceTest",
        ConfYamlSecondLevelSequenceTest, 1);
    UtRegisterTest("ConfYamlEnvVarExpandTest", ConfYamlEnvVarExpandTest, 1);
    UtRegisterTest("ConfYamlEnvVarExpandTestWithDefaultValue", 
                   ConfYamlEnvVarExpandTestWithDefaultValue, 1);
#endif /* UNITTESTS */
}
