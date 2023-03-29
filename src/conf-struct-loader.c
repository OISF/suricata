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

/* Threading modules indices */
typedef struct ThreadingModulesIdx {
    int invalid;
    int management;
    int worker;
} ThreadingModulesIdx;

/* Default output modules indices.
 * These can change if we load a yaml file and we need to make sure we avoid ending up with
   overlapping indices. */
static OutputModulesIdx default_output_modules_idx = {-1, 1, 3, 6, 9};

/* Default logging modules indices. */
static LoggingModulesIdx default_logging_modules_idx = {-1, 0, 1, 2};

/* Default threading modules indices. */
static ThreadingModulesIdx default_threading_modules_idx = {-1, 0, 1};

/* List of configuration nodes that are sequence objects in the yaml and a comma separated string
 * in the configuration struct. */
static const char *sequenceNodes[] = {
    "action-order",
    "callback.nta.dns.types",
    "callback.nta.tls.custom",
    "file-store.force-hash",
    "rule-files",
    "lua.scripts",
    NULL,
};

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
    int idx = default_output_modules_idx.invalid;
    const char *prefix = NULL;
    const char *suffix = NULL;
    if(strncmp(out, "outputs", 7) == 0) {
        if (strncmp(out + 8, "file-store", 10) == 0) {
            idx = default_output_modules_idx.filestore;
        } else if (strncmp(out + 8, "callback", 8) == 0) {
            idx = default_output_modules_idx.callback;
        } else if (strncmp(out + 8, "content-snip", 12) == 0) {
            idx = default_output_modules_idx.content_snip;
        } else if (strncmp(out + 8, "lua", 3) == 0) {
            idx = default_output_modules_idx.lua;
        }
        prefix = "outputs";
    } else if (strncmp(out, "logging.outputs", 15) == 0) {
        if (strncmp(out + 16, "console", 7) == 0) {
            idx = default_logging_modules_idx.console;
        } else if (strncmp(out + 16, "file", 4) == 0) {
            idx = default_logging_modules_idx.file;
        } else if (strncmp(out + 16, "callback", 8) == 0) {
            idx = default_logging_modules_idx.callback;
        }

        prefix = "logging.outputs";
    } else if (strncmp(out, "threading.cpu-affinity", 22) == 0) {
        int offset = 23;
        if (strncmp(out + offset, "management-cpu-set", 18) == 0) {
            idx = default_threading_modules_idx.management;
            offset += 19;
        } else if (strncmp(out + 23, "worker-cpu-set", 14) == 0) {
            idx = default_threading_modules_idx.worker;
            offset += 15;
        }
        prefix = "threading.cpu-affinity";

        /* Check if we have a nested sequence object. */
        if (strstr(out + offset, "cpu") != NULL || strstr(out + offset, "low") != NULL ||
            strstr(out + offset, "medium") != NULL || strstr(out + offset, "high") != NULL) {
            suffix = "0";
        }
    }

    if (idx == default_output_modules_idx.invalid) {
        /* Nothing to do */
        return out;
    }

    /* We need to add room for the index, the dot and NULL. */
    int idx_copy = idx;
    int n_digits = 0;
        do {
        idx_copy /= 10;
        ++n_digits;
    } while (idx_copy != 0);

    size_t node_len = strlen(out) + n_digits + 2;

    if (suffix != NULL) {
        node_len += strlen(suffix) + 1;
    }

    char *node_name_ext = SCMalloc(node_len * sizeof(char));
    if (node_name_ext == NULL) {
        /* Something is off, just return the field without further modifications. */
        return out;
    }

    snprintf(node_name_ext, node_len, "%s.%d.%s", prefix, idx, out + strlen(prefix) + 1);

    if (suffix != NULL) {
        int offset = node_len - (strlen(suffix) + 2);
        snprintf(node_name_ext + offset, node_len, ".%s", suffix);
    }

    /* Swap out with node_name_ext. */
    SCFree((void *)out);
    out = node_name_ext;

    return out;
}

/** \brief Update the modules indices.
 *         When reading the configuration from a yaml file, the module indixes might differ from
 *         the defaults defined above and need to be udpated.
 */
static void CfgUpdateModuleIndices(void) {
    /* Outputs. */
    ConfNode *module = ConfGetNode("outputs");
    if (module != NULL) {
        ConfNode *output, *child;

        TAILQ_FOREACH(output, &module->head, next) {
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

    /* Logging. */
    module = ConfGetNode("logging.outputs");
    if (module != NULL) {
        ConfNode *output, *child;

        TAILQ_FOREACH(output, &module->head, next) {
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

    /* Threading. */
    module = ConfGetNode("threading.cpu-affinity");
    if (module != NULL) {
        ConfNode *output, *child;

        TAILQ_FOREACH(output, &module->head, next) {
            child = ConfNodeLookupChild(output, output->val);

            if (child == NULL) {
                /* Should not happen but ignore anyway. */
                continue;
            }

            if (strncmp(child->name, "management", 10) == 0) {
                default_threading_modules_idx.management = atoi(output->name);
            } else if (strncmp(child->name, "worker", 6) == 0) {
                default_threading_modules_idx.worker = atoi(output->name);
            }
        }
    }
}


/** \brief Check if a configuration node is a sequence formatted as a comma separated string.
 *         Sequence objects in the configuration struct (formatted as comma separated string) need
 *         to be unwrapped in the suricata ConfNode object.
 *
 * \param name   The name of the configuration node to check.
 * \return int   1 on success, 0 on failure.
 */
static int CfgIsNodeSequenceAsString(const char *name) {
    int i = 0;

    while (sequenceNodes[i] != NULL) {
        if (strstr(name, sequenceNodes[i]) != NULL) {
            /* If we are matching on index 3 ("lua.scripts") we meed too make sure we don't have a
             * collision on "lua.scripts-dir". Need to find a better solution for this. */
            if (i == 5 && strstr(name, "lua.scripts-dir") != NULL) {
                return 0;
            }

            /* Match found. */
            return 1;
        }

        i++;
    }

    return 0;
}

/** \brief Convert a yaml sequence object into a comma separated string to be set in the
 *         configuration struct.
 *
 * \param name   The name of the configuration node to convert.
 * \param out    The output parameter that will contain the converted node.
 * \return int   1 on success, 0 on failure.
 */
static int CfgConvertSequenceToString(const char *name, char *out) {
    ConfNode *node;
    node = ConfGetNode(name);
    if (node == NULL) {
        return 0;
    }

    ConfNode *value;
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
        i += snprintf(out + i, value_len + 2, "%s,", value->val);
    }

    if (i == 0) {
        /* No values in the sequence. */
        return 0;
    }

    /* Remove trailing ','. */
    out[i - 1] = '\0';
    return 1;
}

/** \brief Convert the relevant yaml sequence objects into a comma separated string and store it in
  *        the configuration object.
  *
  * \param  cfg    The SuricataCfg object.
  */
static void CfgLoadSequences(SuricataCfg *cfg) {
    char out[NODE_VALUE_MAX];
    char name[64];

    if (CfgConvertSequenceToString("action-order", out)) {
        if (cfg->action_order) {
            SCFree((void *)cfg->action_order);
        }
        cfg->action_order = SCStrdup(out);
    }

    if (CfgConvertSequenceToString("rule-files", out)) {
        if (cfg->rule_files) {
            SCFree((void *)cfg->rule_files);
        }
        cfg->rule_files = SCStrdup(out);
    }

    snprintf(name, sizeof(name), "outputs.%d.callback.nta.dns.types",
             default_output_modules_idx.callback);
    if (CfgConvertSequenceToString(name, out)) {
        if (cfg->outputs0callback0nta0dns0types) {
            SCFree((void *)cfg->outputs0callback0nta0dns0types);
        }
        cfg->outputs0callback0nta0dns0types = SCStrdup(out);
    }

    snprintf(name, sizeof(name), "outputs.%d.callback.nta.tls.custom",
             default_output_modules_idx.callback);
    if (CfgConvertSequenceToString(name, out)) {
        if (cfg->outputs0callback0nta0tls0custom) {
            SCFree((void *)cfg->outputs0callback0nta0tls0custom);
        }
        cfg->outputs0callback0nta0tls0custom = SCStrdup(out);
    }

    snprintf(name, sizeof(name), "outputs.%d.file-store.force-hash",
             default_output_modules_idx.filestore);
    if (CfgConvertSequenceToString(name, out)) {
        if (cfg->outputs0file_store0force_hash) {
            SCFree((void *)cfg->outputs0file_store0force_hash);
        }
        cfg->outputs0file_store0force_hash = SCStrdup(out);
    }

    snprintf(name, sizeof(name), "outputs.%d.lua.scripts", default_output_modules_idx.lua);
    if (CfgConvertSequenceToString(name, out)) {
        if (cfg->outputs0lua0scripts) {
            SCFree((void *)cfg->outputs0lua0scripts);
        }
        cfg->outputs0lua0scripts = SCStrdup(out);
    }
}

/** \brief Finalize the sequence nodes in the suricata ConfNode tree.
  *
  * \param  cfg    The SuricataCfg object.
  */
static void CfgFinalizeSequences(SuricataCfg *cfg) {
    char node_name[64] = {0};

    /* Outputs. */
    snprintf(node_name, sizeof(node_name), "outputs.%d", default_output_modules_idx.filestore);
    ConfSetFinal(node_name, "file-store");

    snprintf(node_name, sizeof(node_name), "outputs.%d", default_output_modules_idx.callback);
    ConfSetFinal(node_name, "callback");

    snprintf(node_name, sizeof(node_name), "outputs.%d", default_output_modules_idx.content_snip);
    ConfSetFinal(node_name, "content-snip");

    snprintf(node_name, sizeof(node_name), "outputs.%d", default_output_modules_idx.lua);
    ConfSetFinal(node_name, "lua");

    /* Logging. */
    snprintf(node_name, sizeof(node_name), "logging.outputs.%d",
             default_logging_modules_idx.console);
    ConfSetFinal(node_name, "console");

    snprintf(node_name, sizeof(node_name), "logging.outputs.%d", default_logging_modules_idx.file);
    ConfSetFinal(node_name, "file");

    snprintf(node_name, sizeof(node_name), "logging.outputs.%d",
             default_logging_modules_idx.callback);
    ConfSetFinal(node_name, "callback");

    /* Threading. */
    snprintf(node_name, sizeof(node_name), "threading.cpu-affinity.%d",
             default_threading_modules_idx.management);
    ConfSetFinal(node_name, "management-cpu-set");

    if (cfg->threading0cpu_affinity0management_cpu_set0cpu) {
        snprintf(node_name, sizeof(node_name),
                 "threading.cpu-affinity.%d.management-cpu-set.cpu.0",
                 default_threading_modules_idx.management);
        ConfSetFinal(node_name, cfg->threading0cpu_affinity0management_cpu_set0cpu);
    }

    snprintf(node_name, sizeof(node_name), "threading.cpu-affinity.%d",
             default_threading_modules_idx.worker);
    ConfSetFinal(node_name, "worker-cpu-set");

    if (cfg->threading0cpu_affinity0worker_cpu_set0cpu) {
        snprintf(node_name, sizeof(node_name),
                 "threading.cpu-affinity.%d.worker-cpu-set.cpu.0",
                 default_threading_modules_idx.worker);
        ConfSetFinal(node_name, cfg->threading0cpu_affinity0worker_cpu_set0cpu);
    }
}

/**
 * \brief Retrieve the default suricata configuration (library mode).
 *
 * \return The suricata configuration.
 */
SuricataCfg CfgGetDefault(void) {
    SuricataCfg c = {
        .default_data_dir = SCStrdup("."),
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
        .outputs0file_store0enabled = SCStrdup("false"),
        .outputs0lua0enabled = SCStrdup("false"),
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

    /* Update module indices after reading the yaml file. */
    CfgUpdateModuleIndices();

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
            const char *copy = SCStrdup(value);                                                 \
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

    /* Handle yaml sequence objects. Those need to be converted in a comma separated string to be
     * stored in the config struct. */
    CfgLoadSequences(cfg);

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
           if (CfgIsNodeSequenceAsString(node_name)) {                                          \
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
    CfgFinalizeSequences(cfg);

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