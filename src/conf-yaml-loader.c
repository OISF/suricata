/* Copyright (c) 2009 Open Information Security Foundation */

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
#include "util-debug.h"
#include "util-unittest.h"

/* Define to print the current YAML state. */
#undef PRINT_STATES
#ifdef PRINT_STATES
#define DPRINT_STATE(x) do { SCLogDebug x ; } while (0)
#else
#define DPRINT_STATE(x)
#endif /* PRINT_STATES */

/* Defines the maximum number of levels YAML may nest.  This is
 * primarily used for construction of lookup-keys for configuration
 * values. */
#define MAX_LEVELS 16

/* Sometimes we'll have to create a node name on the fly (integer
 * conversion, etc), so this is a default length to allocate that will
 * work most of the time. */
#define DEFAULT_NAME_LEN 16

/* Configuration processing states. */
enum conf_state {
    CONF_KEY = 0,
    CONF_VAL,
    CONF_SEQ,
};

/**
 * \brief Return the name of the current configuration key value.
 *
 * This function returns the current value of the configuration key.
 * This is all the key components joined together with a ".".
 *
 * NOTE: This function is not re-entrant safe, but we do not expect to
 * be loading configuration files concurrently.
 */
static char *
GetKeyName(char **key, int level)
{
    /* Statically allocate a string that should be large enough. */
    static char print_key[1024];
    int i;

    print_key[0] = '\0';

    for (i = 0; i <= level; i++) {
        if (key[i] == NULL)
            break;
        if (strlen(key[i]) + strlen(print_key) + 2 > sizeof(print_key)) {
            /* Overflow. */
            return NULL;
        }
        else {
            strncat(print_key, key[i], strlen(key[i]));
            if (i < level)
                strncat(print_key, ".", 1);
        }
    }

    return print_key;
}

/**
 * \brief Parse a YAML layer.
 *
 * This will eventually replace ConfYamlParse but for now its just
 * used to load lists.
 *
 * \param parser A pointer to an active yaml_parser_t.
 * \param parent The parent configuration node.
 */
static void
ConfYamlParse2(yaml_parser_t *parser, ConfNode *parent, int inseq)
{
    ConfNode *node = parent;
    yaml_event_t event;
    int done = 0;
    int state = 0;
    int seq_idx = 0;

    while (!done) {
        if (!yaml_parser_parse(parser, &event)) {
            fprintf(stderr, "Failed to parse configuration file: %s\n",
                parser->problem);
            exit(EXIT_FAILURE);
        }

        if (event.type == YAML_SCALAR_EVENT) {
            char *value = (char *)event.data.scalar.value;
            if (inseq) {
                ConfNode *seq_node = ConfNodeNew();
                seq_node->name = calloc(1, DEFAULT_NAME_LEN);
                snprintf(seq_node->name, DEFAULT_NAME_LEN, "%d", seq_idx++);
                seq_node->val = strdup(value);
                TAILQ_INSERT_TAIL(&parent->head, seq_node, next);
            }
            else {
                if (state == CONF_KEY) {
                    node = ConfNodeNew();
                    node->name = strdup((char *)event.data.scalar.value);
                    TAILQ_INSERT_TAIL(&parent->head, node, next);
                    state = CONF_VAL;
                }
                else {
                    node->val = strdup((char *)event.data.scalar.value);
                    state = CONF_KEY;
                }
            }
        }
        else if (event.type == YAML_SEQUENCE_START_EVENT) {
            state = CONF_SEQ;
        }
        else if (event.type == YAML_SEQUENCE_END_EVENT) {
            return;
        }
        else if (event.type == YAML_MAPPING_START_EVENT) {
            if (inseq) {
                ConfNode *seq_node = ConfNodeNew();
                seq_node->name = calloc(1, DEFAULT_NAME_LEN);
                snprintf(seq_node->name, DEFAULT_NAME_LEN, "%d", seq_idx++);
                TAILQ_INSERT_TAIL(&node->head, seq_node, next);
                ConfYamlParse2(parser, seq_node, 0);
            }
            else {
                ConfYamlParse2(parser, node, inseq);
            }
            state ^= CONF_VAL;
        }
        else if (event.type == YAML_MAPPING_END_EVENT) {
            done = 1;
        }
        else if (event.type == YAML_STREAM_END_EVENT) {
            done = 1;
        }

        yaml_event_delete(&event);
    }
}

/**
 * \brief Process a YAML parser.
 *
 * Loads a configuration from a setup YAML parser.
 *
 * \param parser A YAML parser setup for processing.
 */
static void
ConfYamlParse(yaml_parser_t *parser)
{
    yaml_event_t event;
    int done;
    int level;
    int state;
    int inseq;
    char *key[MAX_LEVELS];

    memset(key, 0, sizeof(key));

    state = CONF_KEY;
    done = 0;
    level = -1;
    inseq = 0;
    while (!done) {
        if (!yaml_parser_parse(parser, &event)) {
            fprintf(stderr, "Failed to parse configuration file: %s\n",
                parser->problem);
            exit(EXIT_FAILURE);
        }
        switch (event.type) {
        case YAML_STREAM_START_EVENT:
            break;
        case YAML_STREAM_END_EVENT:
            done = 1;
            break;
        case YAML_DOCUMENT_START_EVENT:
            /* Ignored. */
            break;
        case YAML_DOCUMENT_END_EVENT:
            /* Ignored. */
            break;
        case YAML_SEQUENCE_START_EVENT: {
            ConfNode *new;
            new = ConfNodeNew();
            new->name = strdup(GetKeyName(key, level));
            ConfYamlParse2(parser, new, 1);
            ConfSetNode(new);
            state = CONF_KEY;
            break;
        }
        case YAML_SEQUENCE_END_EVENT:
            break;
        case YAML_MAPPING_START_EVENT:
            level++;
            if (level == MAX_LEVELS) {
                fprintf(stderr,
                    "Reached maximum configuration nesting level.\n");
                exit(EXIT_FAILURE);
            }

            /* Since we are entering a new mapping, state goes back to key. */
            state = CONF_KEY;

            break;
        case YAML_MAPPING_END_EVENT:
            if (level > -1) {
                free(key[level]);
                key[level] = NULL;
            }
            level--;
            break;
        case YAML_SCALAR_EVENT:
            if (state == CONF_KEY) {
                if (key[level] != NULL)
                    free(key[level]);
                key[level] = strdup((char *)event.data.scalar.value);

                /* Move state to expecting a value. */
                state = CONF_VAL;
            }
            else if (state == CONF_VAL) {
                ConfSet(GetKeyName(key, level), (char *)event.data.scalar.value,
                    1);
                state = CONF_KEY;
            }
            break;
        case YAML_ALIAS_EVENT:
            break;
        case YAML_NO_EVENT:
            break;
        }
        yaml_event_delete(&event);
    }
}

/**
 * \brief Load configuration from a YAML file.
 */
void
ConfYamlLoadFile(const char *filename)
{
    FILE *infile;
    yaml_parser_t parser;

    if (yaml_parser_initialize(&parser) != 1) {
        fprintf(stderr, "Failed to initialize yaml parser.\n");
        exit(EXIT_FAILURE);
    }

    infile = fopen(filename, "r");
    if (infile == NULL) {
        fprintf(stderr, "Failed to open file: %s: %s\n", filename,
            strerror(errno));
        exit(EXIT_FAILURE);
    }
    yaml_parser_set_input_file(&parser, infile);
    ConfYamlParse(&parser);
    yaml_parser_delete(&parser);
    fclose(infile);
}

/**
 * \brief Load configuration from a YAML string.
 */
void
ConfYamlLoadString(const char *string, size_t len)
{
    yaml_parser_t parser;

    if (yaml_parser_initialize(&parser) != 1) {
        fprintf(stderr, "Failed to initialize yaml parser.\n");
        exit(EXIT_FAILURE);
    }
    yaml_parser_set_input_string(&parser, (const unsigned char *)string, len);
    ConfYamlParse(&parser);
    yaml_parser_delete(&parser);
}

#ifdef UNITTESTS

static int
ConfYamlRuleFileTest(void)
{
    char input[] = "\
rule-files:\n\
  - netbios.rules\n\
  - x11.rules\n\
\n\
default-log-dir: /tmp\n\
";

    ConfNode *node;
    ConfYamlLoadString(input, strlen(input));
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

    return 1;
}

static int
ConfYamlLoggingOutputTest(void)
{
    char input[] = "\
logging:\n\
  output:\n\
    - interface: console\n\
      log-level: error\n\
    - interface: syslog\n\
      facility: local4\n\
      log-level: info\n\
";

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

    return 1;
}

#endif /* UNITTESTS */

void
ConfYamlRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("ConfYamlRuleFileTest", ConfYamlRuleFileTest, 1);
    UtRegisterTest("ConfYamlLoggingOutputTest", ConfYamlLoggingOutputTest, 1);
#endif /* UNITTESTS */
}
