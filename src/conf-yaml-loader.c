/* Copyright (c) 2009 Open Information Security Foundation */

/**
 * \file
 *
 * \author Endace Technology Limited - Jason Ish <jason.ish@endace.com>
 *
 * YAML configuration loader.
 */

#include "eidps-common.h"
#include <yaml.h>
#include "conf.h"
#include "util-debug.h"

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

/* Configuration processing states. */
enum conf_state {
    CONF_KEY = 0,
    CONF_VAL,
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
 * \brief Load a configuration file.
 *
 * Loads the IDS configuration file.  On failure, the program will
 * exist with an error message.
 *
 * \param filename Name of the filename to load.
 */
void
LoadYamlConf(const char *filename)
{
    FILE *conf_file;
    yaml_parser_t parser;
    yaml_event_t event;
    int done;
    int level;
    int state;
    int inseq;
    char *key[MAX_LEVELS];

    memset(key, 0, sizeof(key));

    if (yaml_parser_initialize(&parser) != 1) {
        fprintf(stderr, "Failed to initialize yaml parser.\n");
        exit(EXIT_FAILURE);
    }

    conf_file = fopen(filename, "r");
    if (conf_file == NULL) {
        fprintf(stderr, "Failed to open file: %s: %s\n", filename,
            strerror(errno));
        exit(EXIT_FAILURE);
    }
    yaml_parser_set_input_file(&parser, conf_file);

    state = CONF_KEY;
    done = 0;
    level = -1;
    inseq = 0;
    while (!done) {
        if (!yaml_parser_parse(&parser, &event)) {
            fprintf(stderr, "Failed to parse configuration file: %s\n",
                parser.problem);
            exit(EXIT_FAILURE);
        }
        if (level > -1) {
            SCLogDebug("current key: %s", GetKeyName(key, level));
        }
        switch (event.type) {
        case YAML_STREAM_START_EVENT:
            DPRINT_STATE(("YAML_STREAM_START_EVENT"));
            break;
        case YAML_STREAM_END_EVENT:
            DPRINT_STATE(("YAML_STREAM_END_EVENT"));
            done = 1;
            break;
        case YAML_DOCUMENT_START_EVENT:
            DPRINT_STATE(("YAML_STREAM_END_EVENT"));
            /* Ignored. */
            break;
        case YAML_DOCUMENT_END_EVENT:
            DPRINT_STATE(("YAML_DOCUMENT_END_EVENT"));
            /* Ignored. */
            break;
        case YAML_SEQUENCE_START_EVENT:
            DPRINT_STATE(("YAML_SEQUENCE_START_EVENT"));
            inseq = 1;
            break;
        case YAML_SEQUENCE_END_EVENT:
            DPRINT_STATE(("YAML_SEQUENCE_END_EVENT"));
            inseq = 0;
            break;
        case YAML_MAPPING_START_EVENT:
            DPRINT_STATE(("YAML_MAPPING_START_EVENT"));
            level++;
            if (level == MAX_LEVELS) {
                fprintf(stderr, "Reached maximum configuration nesting level.\n");
                exit(EXIT_FAILURE);
            }

            /* Since we are entering a new mapping, state goes back to key. */
            state = CONF_KEY;

            break;
        case YAML_MAPPING_END_EVENT:
            DPRINT_STATE(("YAML_MAPPING_END_EVENT"));
            if (level > -1) {
                free(key[level]);
                key[level] = NULL;
            }
            level--;
            break;
        case YAML_SCALAR_EVENT:
            DPRINT_STATE(("YAML_SCALAR_EVENT"));
            if (inseq) {
                if (level > -1) {
                    SCLogDebug("ignoring sequence value for %s", GetKeyName(key, level));
                }
                break;
            }
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
            DPRINT_STATE(("YAML_ALIAS_EVENT"));
            break;
        case YAML_NO_EVENT:
            DPRINT_STATE(("YAML_NO_EVENT"));
            break;
        }
        yaml_event_delete(&event);
    }

    yaml_parser_delete(&parser);
    fclose(conf_file);
}
