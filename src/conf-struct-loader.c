/** \file
 *
 *  \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 *  Configuration from config object.
 */

#include "suricata-common.h"
#include "conf-struct-loader.h"
#include "conf-yaml-loader.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "conf.h"
#include "util-debug.h"

/* Maximum length for a node value (used when converting sequence values in comma separated
 * string). */
#define NODE_VALUE_MAX 8192


/* Output modules indices */
typedef struct OutputModulesIdx {
    int invalid;
    int filestore;
    int content_snip;
    int callback;
    int lua;
} OutputModulesIdx;

/* Logging modules indices */
typedef struct LoggingModulesIdx {
    int invalid;
    int console;
    int file;
    int callback;
} LoggingModulesIdx;

/* Default output modules indices.
 * These can change if we load a yaml file and we need to make sure we avoid ending up with
   overlapping indices. */
static OutputModulesIdx default_output_modules_idx = {-1, 1, 3, 6, 9};

/* Default logging modules indices. */
static LoggingModulesIdx default_logging_modules_idx = {-1, 0, 1, 2};

/** \brief Mangle a SuricataCfg field into the format of the Configuration tree.
  *        This means replacing '_' characters with '-' and '0' with '.'.
  *        Allow '_' within the "vars" leaf nodes.
  *        For output modules (filestore/flowsnip) we also need to add the index as it is a
  *        sequence in the yaml.
  *
  * \param field           The SuricataCfg field.
  * \param idx_from_yaml   The output module sequence index when loading a yaml file.
  * \return const char *   The mangled field.
  */
static const char *mangleCfgField(const char *field) {
    char *out = SCStrdup(field);

    if (unlikely(out == NULL)) {
        return out;
    }

    int i = 0;
    while (out[i]) {
        if (out[i] == '_' && strncmp(out, "vars.address-groups.", 20) != 0
            && strncmp(out, "vars.port-groups.", 17) != 0) {
            out[i] = '-';
        } else if (out[i] == '0') {
            out[i] = '.';
        }

        i++;
    }

    /* Check if it is a supported output module and extend the name to include the sequence
     * index. */
    if(strncmp(out, "outputs", 7) == 0) {
        uint8_t idx = default_output_modules_idx.invalid;

        if (strncmp(out + 8, "file-store", 10) == 0) {
            idx = default_output_modules_idx.filestore;
        } else if (strncmp(out + 8, "callback", 8) == 0) {
            idx = default_output_modules_idx.callback;
        } else if (strncmp(out + 8, "content-snip", 12) == 0) {
            idx = default_output_modules_idx.content_snip;
        } else if (strncmp(out + 8, "lua", 3) == 0) {
            idx = default_output_modules_idx.lua;
        }

        if (idx == default_output_modules_idx.invalid) {
            /* Something is off, just return the field without further modifications. */
            return out;
        }

        /* We need to add room for the index, the dot and NULL. */
        int n_digits = 0;
        int idx_copy = idx;
         do {
            idx_copy /= 10;
            ++n_digits;
        } while (idx_copy != 0);

        size_t node_len = strlen(out) + n_digits + 2;
        char *node_name_ext = SCMalloc(node_len * sizeof(char));

        if (node_name_ext == NULL) {
            /* Something is off, just return the field without further modifications. */
            return out;
        }

        snprintf(node_name_ext, node_len + 1, "outputs.%d.%s", idx, out + 8);

        /* Swap out with node_name_ext. */
        SCFree((void *)out);
        out = node_name_ext;
    } else if (strncmp(out, "logging.outputs", 15) == 0) {
        /* Same process for logging modules. */
        uint8_t idx = default_logging_modules_idx.invalid;

        if (strncmp(out + 16, "console", 7) == 0) {
            idx = default_logging_modules_idx.console;
        } else if (strncmp(out + 16, "file", 4) == 0) {
            idx = default_logging_modules_idx.file;
        } else if (strncmp(out + 16, "callback", 8) == 0) {
            idx = default_logging_modules_idx.callback;
        }

        if (idx == default_logging_modules_idx.invalid) {
            /* Something is off, just return the field without further modifications. */
            return out;
        }

        /* Assume a single digit is enough (there are not that many logging modules). */
        size_t node_len = strlen(out) + 3;
        char *node_name_ext = SCMalloc(node_len * sizeof(char));

        if (node_name_ext == NULL) {
            /* Something is off, just return the field without further modifications. */
            return out;
        }

        snprintf(node_name_ext, node_len + 1, "logging.outputs.%d.%s", idx, out + 16);

        /* Swap out with node_name_ext. */
        SCFree((void *)out);
        out = node_name_ext;
    }

    return out;
}

/** \brief Convert a yaml sequence object into a comma separated list of values and store it in
  *        the configuration object. Currently used by the "rule-files" and
  *        "output.callbacks.nta.tls.custom" nodes.
  *
  * \param cfg    The SuricataCfg object.
  * \param name   The name of the configuration node to convert.
  */
static void CfgSetSequence(SuricataCfg *cfg, const char *name) {
    ConfNode *node;
    node = ConfGetNode(name);
    if (node == NULL) {
        return;
    }

    ConfNode *value;
    char values[NODE_VALUE_MAX];
    int i = 0;

    TAILQ_FOREACH(value, &node->head, next) {
        size_t value_len = strlen(value->val);
        if (value_len + i + 1 >= NODE_VALUE_MAX) {
            /* Maximum length reached, we cannot store anymore values. */
            SCLogWarning("Reached maximum size for node %s, not storing value %s and following",
                         name, value->val);
            break;
        }
        /* Append the filename. */
        i += snprintf(values + i, value_len + 2, "%s,", value->val);
    }

    if (i == 0) {
        /* No values in the sequence. */
        return;
    }

    /* Remove trailing ','. */
    values[i - 1] = '\0';

    if (strncmp(name, "rule-files", 10) == 0) {
        if (cfg->rule_files) {
            SCFree((void *)cfg->rule_files);
        }
        cfg->rule_files = SCStrdup(values);
    } else if (strstr(name, "callback.nta.tls.custom") != NULL) {
        if (cfg->outputs0callback0nta0tls0custom) {
            SCFree((void *)cfg->outputs0callback0nta0tls0custom);
        }
        cfg->outputs0callback0nta0tls0custom = SCStrdup(values);
    } else if (strstr(name, "lua.scripts") != NULL) {
        if (cfg->outputs0lua0scripts) {
            SCFree((void *)cfg->outputs0lua0scripts);
        }
        cfg->outputs0lua0scripts = SCStrdup(values);
    } else if (strstr(name, "file-store.force-hash") != NULL) {
        if (cfg->outputs0file_store0force_hash) {
            SCFree((void *)cfg->outputs0file_store0force_hash);
        }
        cfg->outputs0file_store0force_hash = SCStrdup(values);
    }
}

/**
 * \brief Retrieve the default suricata configuration (library mode).
 *
 * \return The suricata configuration.
 */
SuricataCfg CfgGetDefault(void) {
    SuricataCfg c = {
        .default_log_dir = SCStrdup("."),
        .default_packet_size = SCStrdup("1538"),
        .mpm_algo = SCStrdup("hs"),
        .spm_algo = SCStrdup("hs"),
        .runmode = SCStrdup("offline"), /* Default for PCAP/Stream replaying. */
        .flow0managers = SCStrdup("1"),
        .flow0recyclers = SCStrdup("1"),
        .logging0outputs0callback0enabled = SCStrdup("false"),
        .luajit0states = SCStrdup("512"),
        .outputs0callback0enabled = SCStrdup("false"),
        .outputs0callback0http0extended = SCStrdup("yes"),
        .outputs0content_snip0enabled = SCStrdup("false"),
        .outputs0content_snip0dir = SCStrdup("pcaps"),
        .outputs0lua0enabled = SCStrdup("false"),
        .outputs0file_store0enabled = SCStrdup("false")
    };
    return c;
}

/**
 * \brief Build the configuration object from yaml (library mode).
 *
 * \param filename Filename of the yaml to load.
 * \param  cfg     The SuricataCfg object.
 * \return         Error code.
 */
int CfgLoadYaml(const char *filename, SuricataCfg *cfg) {
    int ret = ConfYamlLoadFile(filename);

    if (ret != 0) {
        SCLogError("Failed to parse configuration file: %s", filename);
        return ret;
    }

    /* Loop over the output modules and update the indices since they might differ from the default
     * ones above. */
    ConfNode *outputs = ConfGetNode("outputs");

    if (outputs != NULL) {
        ConfNode *output, *child;

        TAILQ_FOREACH(output, &outputs->head, next) {
            child = ConfNodeLookupChild(output, output->val);

            if (child == NULL) {
                /* Should not happen but ignore anyway. */
                continue;
            }

            if (strncmp(child->name, "file-store", 10) == 0) {
                default_output_modules_idx.filestore = atoi(output->name);
            } else if (strncmp(child->name, "callback", 8) == 0) {
                default_output_modules_idx.callback = atoi(output->name);
            } else if (strncmp(child->name, "content-snip", 12) == 0) {
                default_output_modules_idx.content_snip = atoi(output->name);
            } else if (strncmp(child->name, "lua", 3) == 0) {
                default_output_modules_idx.lua = atoi(output->name);
            }
        }
    }

    /* Same process for the logging modules. */
    outputs = ConfGetNode("logging.outputs");
    if (outputs != NULL) {
        ConfNode *output, *child;

        TAILQ_FOREACH(output, &outputs->head, next) {
            child = ConfNodeLookupChild(output, output->val);

            if (child == NULL) {
                /* Should not happen but ignore anyway. */
                continue;
            }

            if (strncmp(child->name, "console", 7) == 0) {
                default_logging_modules_idx.console = atoi(output->name);
            } else if (strncmp(child->name, "file", 4) == 0) {
                default_logging_modules_idx.file = atoi(output->name);
            } else if (strncmp(child->name, "callback", 8) == 0) {
                default_logging_modules_idx.callback = atoi(output->name);
            }
        }
    }

    /* Configuration is now parsed. Iterate over the struct fields, setting the relevant fields. */
#define CFG_ENTRY(name) do {                                                                    \
        const char *node_name = mangleCfgField(#name);                                          \
        if (!node_name) {                                                                       \
            SCLogError("Failed to mangle config field: %s", #name);                             \
            return -1;                                                                          \
        }                                                                                       \
                                                                                                \
        const char *value;                                                                      \
        if (ConfGetValue(node_name, &value) == 1) {                                             \
           const char *copy = SCStrdup(value);                                                  \
            if (unlikely(copy == NULL)) {                                                       \
                SCLogError("Failed to allocate memory for config node: %s", node_name);         \
                SCFree((void *)node_name);                                                      \
                return -1;                                                                      \
            }                                                                                   \
                                                                                                \
            /* Override (free) the current value, if set. */                                    \
            if (cfg->name) {                                                                    \
                SCFree((void *)cfg->name);                                                      \
            }                                                                                   \
            cfg->name = copy;                                                                   \
        }                                                                                       \
        SCFree((void *)node_name);                                                              \
    } while(0);

    CFG_FIELDS
#undef CFG_ENTRY

    /* Handle "rule-files", "outputs.callback.nta.tls.custom" and "outputs.lua.scripts" and
     * "outputs.filestore.force-hash" separately as they are a sequence objects in the yaml. */
    CfgSetSequence(cfg, "rule-files");

    char name[64];
    snprintf(name, sizeof(name), "outputs.%d.callback.nta.tls.custom",
             default_output_modules_idx.callback);
    CfgSetSequence(cfg, name);

    snprintf(name, sizeof(name), "outputs.%d.lua.scripts", default_output_modules_idx.lua);
    CfgSetSequence(cfg, name);

    snprintf(name, sizeof(name), "outputs.%d.file-store.force-hash",
             default_output_modules_idx.filestore);
    CfgSetSequence(cfg, name);

    /* Deinit reinit the configuration tree used later by the engine. */
    ConfDeInit();
    ConfInit();

    return ret;
}

/** \brief Setup configuration from the given object.
  *
  * \param  cfg      The SuricataCfg object.
  * \return          Error code.
  */
int CfgLoadStruct(SuricataCfg *cfg) {
    /* Iterate over the struct fields and set them into the configuration tree. */
#define CFG_ENTRY(name) do {                                                                    \
        if (cfg->name) {                                                                        \
           const char *node_name = mangleCfgField(#name);                                       \
           int ret = 0;                                                                         \
           if (!node_name) {                                                                    \
               SCLogError("Failed to mangle config field: %s", #name);                          \
               return !ret;                                                                     \
           }                                                                                    \
                                                                                                \
           /* TODO: this is ugly, refactor at some point. */                                    \
           if (strncmp(node_name, "rule-files", 10) == 0 ||                                     \
               strstr(node_name, "callback.nta.tls.custom") != NULL ||                          \
               (strstr(node_name, "lua.scripts") != NULL &&                                     \
                strstr(node_name, "lua.scripts-dir") == NULL) ||                                \
               strstr(node_name, "file-store.force-hash") != NULL) {                            \
               /* Handle these nodes differently because they are a sequence of comma           \
                * separated values. */                                                          \
               ret = ConfSetFromSequence(node_name, cfg->name);                                 \
           } else {                                                                             \
               ret = ConfSetFinal(node_name, cfg->name);                                        \
           }                                                                                    \
           SCFree((void *)node_name);                                                           \
           if(!ret) {                                                                           \
               SCLogError("Failed to set config option: %s - %s", #name, cfg->name);            \
               return !ret;                                                                     \
           }                                                                                    \
        }                                                                                       \
    } while(0);

    CFG_FIELDS
#undef CFG_ENTRY

    /* Need to set in the configuration tree an additional node for each output module as it is
     * a sequence in the yaml. */
    char node_name[32] = {0};

    snprintf(node_name, 32, "outputs.%d", default_output_modules_idx.filestore);
    ConfSetFinal(node_name, "file-store");

    snprintf(node_name, 32, "outputs.%d", default_output_modules_idx.callback);
    ConfSetFinal(node_name, "callback");

    snprintf(node_name, 32, "outputs.%d", default_output_modules_idx.content_snip);
    ConfSetFinal(node_name, "content-snip");

    snprintf(node_name, 32, "outputs.%d", default_output_modules_idx.lua);
    ConfSetFinal(node_name, "lua");

    snprintf(node_name, 32, "logging.outputs.%d", default_logging_modules_idx.console);
    ConfSetFinal(node_name, "console");

    snprintf(node_name, 32, "logging.outputs.%d", default_logging_modules_idx.file);
    ConfSetFinal(node_name, "file");

    snprintf(node_name, 32, "logging.outputs.%d", default_logging_modules_idx.callback);
    ConfSetFinal(node_name, "callback");

    return 0;
}

/** \brief Set a configuration option by key.
  *
  * \param cfg       The SuricataCfg object.
  * \param key       The configuration option key.
  * \param val       The configuration option value.
  *
  * \return          1 If set, 0 if not set.
  */
int CfgSet(SuricataCfg *cfg, const char *key, const char *val) {
    if (key == NULL || val == NULL) {
        return 0;
    }

    const char * mangled_key = mangleCfgField(key);

    #define CFG_ENTRY(name) do {                                                                \
        const char *node_name = mangleCfgField(#name);                                          \
        if (node_name && strcmp(node_name, mangled_key) == 0) {                                 \
            const char *copy = SCStrdup(val);                                                   \
            if (copy != NULL) {                                                                 \
                /* Override (free) the current value, if set. */                                \
                if (cfg->name) {                                                                \
                    SCFree((void *)cfg->name);                                                  \
                }                                                                               \
                                                                                                \
                cfg->name = copy;                                                               \
                SCFree((void *)node_name);                                                      \
                SCFree((void *)mangled_key);                                                    \
                return 1;                                                                       \
            }                                                                                   \
        }                                                                                       \
        SCFree((void *)node_name);                                                              \
    } while(0);

    CFG_FIELDS
#undef CFG_ENTRY

    SCFree((void *)mangled_key);
    return 0;
}

/** \brief Free the configuration object.
  *
  * \param cfg       The SuricataCfg object.
  */
void CfgFree(SuricataCfg *cfg) {
    #define CFG_ENTRY(name) do {             \
        if (cfg->name != NULL) {             \
            SCFree((void *)cfg->name);       \
        }                                    \
    } while(0);

    CFG_FIELDS
#undef CFG_ENTRY
}