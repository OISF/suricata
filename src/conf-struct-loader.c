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

/* Maximum length for a node value (only used to handle rule-files and output modules). */
#define NODE_VALUE_MAX 4096


/* Output modules indices corresponding to their index in the yaml sequence.
 * This means that right now the order of the output modules in the yaml matters (need to probably
 * adjust it later).
 */
typedef enum OutputModulesIdx {
    OUTPUT_MODULE_STATS = 1,
    OUTPUT_MODULE_FILESTORE,
    OUTPUT_MODULE_INVALID
} OutputModulesIdx;

/** \brief Mangle a SuricataCfg field into the format of the Configuration tree.
  *        This means replacing '_' characters with '-' and '0' with '.'.
  *        Allow '_' within the "vars" leaf nodes.
  *        For output modules (filestore/stats) we also need to add the index as it is a sequence
  *        in the yaml.
  *
  * \param field           The SuricataCfg field.
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
        OutputModulesIdx idx = OUTPUT_MODULE_INVALID;

        if (strncmp(out + 8, "file-store", 10) == 0) {
            idx = OUTPUT_MODULE_FILESTORE;
        } else if (strncmp(out + 8, "stats", 5) == 0) {
            idx = OUTPUT_MODULE_STATS;
        }

        if (idx == OUTPUT_MODULE_INVALID) {
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
        .outputs0file_store0version = SCStrdup("2"),
        .outputs0file_store0enabled = SCStrdup("yes"),
        .outputs0file_store0force_magic = SCStrdup("yes"),
        .outputs0file_store0dir = SCStrdup("files"),
        .outputs0file_store0stream_depth = SCStrdup("0"),
        .outputs0stats0enabled = SCStrdup("yes"),
        .outputs0stats0append = SCStrdup("true"),
        .outputs0stats0totals = SCStrdup("yes"),
        .outputs0stats0threads = SCStrdup("no"),
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
    /* TODO: handle environment variables in yaml (e.g $VXLAN_PORTS). */
    int ret = ConfYamlLoadFile(filename);

    if (ret != 0) {
        SCLogError("Failed to parse configuration file: %s", filename);
        return ret;
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

    /* Handle "rule-files" separately because it is a sequence. */
    ConfNode *node;
    node = ConfGetNode("rule-files");
    if (node != NULL) {
        ConfNode *filename;
        char *rule_files = SCMalloc(NODE_VALUE_MAX * sizeof(char));
        if (rule_files == NULL) {
            SCLogError("Failed to allocate memory for rule files");
            ConfDeInit();
            ConfInit();
            return -1;
        }

        int i = 0;
        TAILQ_FOREACH(filename, &node->head, next) {
            size_t filename_len = strlen(filename->val);
            if (filename_len + i + 1 >= NODE_VALUE_MAX) {
                /* Maximum length reached, we cannot store anymore files. */
                SCLogWarning("Reached maximum size for rule files, not storing %s and following",
                             filename->val);
                break;
            }
            /* Append the filename. */
            i += snprintf(rule_files + i, filename_len + 2, "%s,", filename->val);
        }
        /* Remove trailing ','. */
        rule_files[i -1] = '\0';

        if (cfg->rule_files) {
            SCFree((void *)cfg->rule_files);
        }
        cfg->rule_files = rule_files;
    }

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
           if (strncmp(node_name, "rule-files", 10) == 0) {                                     \
               /* Rule files are handled differently because they are a sequence of comma       \
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
    if (cfg->outputs0file_store0enabled != NULL) {
        char node_name[10] = {0};
        snprintf(node_name, 10, "outputs.%d", OUTPUT_MODULE_FILESTORE);
        ConfSetFinal(node_name, "file-store");
    }
    if (cfg->outputs0stats0enabled != NULL) {
        char node_name[10] = {0};
        snprintf(node_name, 10, "outputs.%d", OUTPUT_MODULE_STATS);
        ConfSetFinal(node_name, "stats");
    }

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

    #define CFG_ENTRY(name) do {                                                                \
        const char *node_name = mangleCfgField(#name);                                          \
        if (node_name && strcmp(node_name, key) == 0) {                                         \
            const char *copy = SCStrdup(val);                                                   \
            if (copy != NULL) {                                                                 \
                /* Override (free) the current value, if set. */                                \
                if (cfg->name) {                                                                \
                    SCFree((void *)cfg->name);                                                  \
                }                                                                               \
                                                                                                \
                cfg->name = copy;                                                               \
                SCFree((void *)node_name);                                                      \
                return 1;                                                                       \
            }                                                                                   \
        }                                                                                       \
        SCFree((void *)node_name);                                                              \
    } while(0);

    CFG_FIELDS
#undef CFG_ENTRY

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