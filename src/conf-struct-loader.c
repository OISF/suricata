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

/* Maximum length for a node value (only used to handle rule-files). */
#define NODE_VALUE_MAX 4096


/* Output modules indices */
typedef struct OutputModulesIdx {
    int invalid;
    int stats;
    int filestore;
    int content_snip;
    int callback;
} OutputModulesIdx;

/* Default output modules indices.
 * These can change if we load a yaml file and we need to make sure we avoid ending up with
   overlapping indices. */
static OutputModulesIdx default_output_modules_idx = {-1, 1, 3, 6, 9};

/** \brief Mangle a SuricataCfg field into the format of the Configuration tree.
  *        This means replacing '_' characters with '-' and '0' with '.'.
  *        Allow '_' within the "vars" leaf nodes.
  *        For output modules (filestore/stats) we also need to add the index as it is a sequence
  *        in the yaml.
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


        if (strncmp(out + 8, "stats", 5) == 0) {
            idx = default_output_modules_idx.stats;
        } else if (strncmp(out + 8, "file-store", 10) == 0) {
            idx = default_output_modules_idx.filestore;
        } else if (strncmp(out + 8, "callback", 8) == 0) {
            idx = default_output_modules_idx.callback;
        } else if (strncmp(out + 8, "content-snip", 12) == 0) {
            idx = default_output_modules_idx.content_snip;
        }

        if (idx == default_output_modules_idx.invalid) {
            /* Something is off, just return the field without further modifications. */
            return out;
        }

        /* We need 2 bytes more than node_name length (plus NULL). */
        size_t node_len = strlen(out) + 3;
        char *node_name_ext = SCMalloc(node_len * sizeof(char));

        if (node_name_ext == NULL) {
            /* Something is off, just return the field without further modifications. */
            return out;
        }

        snprintf(node_name_ext, node_len + 1, "outputs.%d.%s", idx, out + 8);

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
    if (node != NULL) {
        ConfNode *value;
        char values[NODE_VALUE_MAX];

        int i = 0;
        TAILQ_FOREACH(value, &node->head, next) {
            size_t value_len = strlen(value->val);
            if (value_len + i + 1 >= NODE_VALUE_MAX) {
                /* Maximum length reached, we cannot store anymore values. */
                SCLogWarning("Reached maximum size for node %s, not storing "
                             "value %s and following", name, value->val);
                break;
            }
            /* Append the filename. */
            i += snprintf(values + i, value_len + 2, "%s,", value->val);
        }
        /* Remove trailing ','. */
        values[i -1] = '\0';

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
        }
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
        .app_layer0protocols0rfb0enabled = SCStrdup("detection-only"),
        .app_layer0protocols0rfb0detection_ports0dp = SCStrdup("5900, 5901, 5902, 5903, 5904, "
                                                               "5905, 5906, 5907, 5908, 5909"),
        .app_layer0protocols0mqtt0enabled = SCStrdup("detection-only"),
        .app_layer0protocols0krb50enabled = SCStrdup("yes"),
        .app_layer0protocols0ikev20enabled = SCStrdup("detection-only"),
        .app_layer0protocols0tls0enabled = SCStrdup("yes"),
        .app_layer0protocols0tls0detection_ports0dp = SCStrdup("443"),
        .app_layer0protocols0tls0ja3_fingerprints = SCStrdup("yes"),
        .app_layer0protocols0tls0encryption_handling = SCStrdup("full"),
        .app_layer0protocols0dcerpc0enabled = SCStrdup("detection-only"),
        .app_layer0protocols0ftp0enabled = SCStrdup("yes"),
        .app_layer0protocols0rdp0enabled = SCStrdup("yes"),
        .app_layer0protocols0ssh0enabled = SCStrdup("detection-only"),
        .app_layer0protocols0http20enabled = SCStrdup("yes"),
        .app_layer0protocols0smtp0enabled = SCStrdup("yes"),
        .app_layer0protocols0smtp0raw_extraction = SCStrdup("yes"),
        .app_layer0protocols0smtp0mime0decode_mime = SCStrdup("no"),
        .app_layer0protocols0smtp0mime0decode_base64 = SCStrdup("yes"),
        .app_layer0protocols0smtp0mime0decode_quoted_printable = SCStrdup("yes"),
        .app_layer0protocols0smtp0mime0header_value_depth = SCStrdup("2000"),
        .app_layer0protocols0smtp0mime0extract_urls = SCStrdup("yes"),
        .app_layer0protocols0smtp0mime0body_md5 = SCStrdup("no"),
        .app_layer0protocols0smtp0inspect_tracker0content_limit = SCStrdup("100000"),
        .app_layer0protocols0smtp0inspect_tracker0content_inspect_min_size = SCStrdup("32768"),
        .app_layer0protocols0smtp0inspect_tracker0content_inspect_window = SCStrdup("4096"),
        .app_layer0protocols0imap0enabled = SCStrdup("detection-only"),
        .app_layer0protocols0smb0enabled = SCStrdup("yes"),
        .app_layer0protocols0smb0detection_ports0dp = SCStrdup("139, 445"),
        .app_layer0protocols0nfs0enabled = SCStrdup("detection-only"),
        .app_layer0protocols0tftp0enabled = SCStrdup("detection-only"),
        .app_layer0protocols0modbus0enabled = SCStrdup("no"),
        .app_layer0protocols0dns0tcp0enabled = SCStrdup("yes"),
        .app_layer0protocols0dns0tcp0detection_ports0dp = SCStrdup("53"),
        .app_layer0protocols0dns0udp0enabled = SCStrdup("yes"),
        .app_layer0protocols0dns0udp0detection_ports0dp = SCStrdup("53"),
        .app_layer0protocols0dnp30enabled = SCStrdup("no"),
        .app_layer0protocols0icap0enabled = SCStrdup("no"),
        .app_layer0protocols0enip0enabled = SCStrdup("no"),
        .app_layer0protocols0ntp0enabled = SCStrdup("detection-only"),
        .app_layer0protocols0dhcp0enabled = SCStrdup("yes"),
        .app_layer0protocols0http0enabled = SCStrdup("yes"),
        .app_layer0protocols0http0libhtp0default_config0personality = SCStrdup("IDS"),
        .app_layer0protocols0http0libhtp0default_config0request_body_limit = SCStrdup("4096"),
        .app_layer0protocols0http0libhtp0default_config0response_body_limit = SCStrdup("8388608"),
        .app_layer0protocols0http0libhtp0default_config0request_body_minimal_inspect_size =
                                                                                 SCStrdup("32768"),
        .app_layer0protocols0http0libhtp0default_config0request_body_inspect_window =
                                                                                 SCStrdup("4096"),
        .app_layer0protocols0http0libhtp0default_config0response_body_minimal_inspect_size =
                                                                                 SCStrdup("32768"),
        .app_layer0protocols0http0libhtp0default_config0response_body_inspect_window =
                                                                                 SCStrdup("4096"),
        .app_layer0protocols0http0libhtp0default_config0prune_multiplier = SCStrdup("3"),
        .app_layer0protocols0http0libhtp0default_config0http_body_inline = SCStrdup("auto"),
        .app_layer0protocols0http0libhtp0default_config0double_decode_path = SCStrdup("yes"),
        .app_layer0protocols0http0libhtp0default_config0path_utf8_convert_bestfit = SCStrdup("no"),
        .app_layer0protocols0http0libhtp0default_config0allow_truncated_output = SCStrdup("false"),
        .app_layer0protocols0http0libhtp0default_config0allow_wrong_cl_extraction =
                                                                                SCStrdup("false"),
        .app_layer0protocols0http0libhtp0default_config0decompression_layers_limit = SCStrdup("2"),
        .app_layer0protocols0http0libhtp0default_config0enable_chunk_non_http11 = SCStrdup("true"),
        .app_layer0protocols0http0libhtp0default_config0force_body_extraction = SCStrdup("false"),
        .app_layer0protocols0http0libhtp0default_config0force_start_http = SCStrdup("false"),
        .app_layer0protocols0http0libhtp0default_config0force_strict_chunked_parse =
                                                                                 SCStrdup("false"),
        .app_layer0protocols0http0libhtp0default_config0loose_empty_line = SCStrdup("false"),
        .app_layer0protocols0http0libhtp0default_config0max_res_ignored_lines = SCStrdup("0"),
        .app_layer0protocols0http0libhtp0default_config0remove_nonprintable_chars_header =
                                                                                 SCStrdup("false"),
        .defrag0memcap = SCStrdup("33554432"),
        .defrag0hash_size = SCStrdup("65536"),
        .defrag0trackers = SCStrdup("65535"),
        .defrag0max_frags = SCStrdup("65535"),
        .defrag0prealloc = SCStrdup("yes"),
        .defrag0timeout = SCStrdup("60"),
        .detect0profile = SCStrdup("medium"),
        .detect0inspection_recursion_limit = SCStrdup("3000"),
        .flow0managers = SCStrdup("1"),
        .flow0recyclers = SCStrdup("1"),
        .luajit0states = SCStrdup("512"),
        .outputs0callback0http0extended = SCStrdup("yes"),
        .outputs0callback0http0xff0enabled = SCStrdup("false"),
        .outputs0content_snip0enabled = SCStrdup("false"),
        .outputs0content_snip0dir = SCStrdup("pcaps"),
        .outputs0file_store0version = SCStrdup("2"),
        .outputs0file_store0enabled = SCStrdup("yes"),
        .outputs0file_store0force_magic = SCStrdup("yes"),
        .outputs0file_store0dir = SCStrdup("files"),
        .outputs0file_store0stream_depth = SCStrdup("0"),
        .stats0enabled = SCStrdup("yes")
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
                /* Should not happne but ignore anyway. */
                continue;
            }

            if (strncmp(child->name, "stats", 5) == 0) {
                default_output_modules_idx.stats = atoi(output->name);
            } else if (strncmp(child->name, "file-store", 10) == 0) {
                default_output_modules_idx.filestore = atoi(output->name);
            } else if (strncmp(child->name, "callback", 8) == 0) {
                default_output_modules_idx.callback = atoi(output->name);
            } else if (strncmp(child->name, "content-snip", 12) == 0) {
                default_output_modules_idx.content_snip = atoi(output->name);
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

    /* Handle "rule-files" and "outputs.callback.nta.tls.custom" separately as they are a
     * sequence objects in the yaml. */
    CfgSetSequence(cfg, "rule-files");
    char name[64];
    snprintf(name, sizeof(name), "outputs.%d.callback.nta.tls.custom",
             default_output_modules_idx.callback);
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
           if (strncmp(node_name, "rule-files", 10) == 0 ||                                     \
               strstr(node_name, "callback.nta.tls.custom") != NULL) {                          \
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
    char node_name[10] = {0};
    snprintf(node_name, 10, "outputs.%d", default_output_modules_idx.stats);
    ConfSetFinal(node_name, "stats");
    snprintf(node_name, 10, "outputs.%d", default_output_modules_idx.filestore);
    ConfSetFinal(node_name, "file-store");
    snprintf(node_name, 10, "outputs.%d", default_output_modules_idx.callback);
    ConfSetFinal(node_name, "callback");
    snprintf(node_name, 10, "outputs.%d", default_output_modules_idx.content_snip);
    ConfSetFinal(node_name, "content-snip");

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
        return -1;
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