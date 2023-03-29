/** \file
 *
 *  \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 *  Configuration from config object.
 */

#ifndef __CONF_STRUCT_LOADER_H__
#define __CONF_STRUCT_LOADER_H__

/* Suricata configuration fields. */
#define CFG_FIELDS                                                                                 \
    CFG_ENTRY(classification_file)                                                                 \
    CFG_ENTRY(default_log_dir)                                                                     \
    CFG_ENTRY(default_packet_size)                                                                 \
    CFG_ENTRY(default_rule_path)                                                                   \
    CFG_ENTRY(max_pending_packets)                                                                 \
    CFG_ENTRY(mpm_algo)                                                                            \
    CFG_ENTRY(spm_algo)                                                                            \
    CFG_ENTRY(reference_config_file)                                                               \
    CFG_ENTRY(rule_files)                                                                          \
    CFG_ENTRY(runmode)                                                                             \
    CFG_ENTRY(app_layer0protocols0rfb0enabled)                                                     \
    CFG_ENTRY(app_layer0protocols0rfb0detection_ports0dp)                                          \
    CFG_ENTRY(app_layer0protocols0mqtt0enabled)                                                    \
    CFG_ENTRY(app_layer0protocols0krb50enabled)                                                    \
    CFG_ENTRY(app_layer0protocols0ikev20enabled)                                                   \
    CFG_ENTRY(app_layer0protocols0tls0enabled)                                                     \
    CFG_ENTRY(app_layer0protocols0tls0detection_ports0dp)                                          \
    CFG_ENTRY(app_layer0protocols0tls0ja3_fingerprints)                                            \
    CFG_ENTRY(app_layer0protocols0tls0encryption_handling)                                         \
    CFG_ENTRY(app_layer0protocols0dcerpc0enabled)                                                  \
    CFG_ENTRY(app_layer0protocols0ftp0enabled)                                                     \
    CFG_ENTRY(app_layer0protocols0ftp0memcap)                                                      \
    CFG_ENTRY(app_layer0protocols0rdp0enabled)                                                     \
    CFG_ENTRY(app_layer0protocols0ssh0enabled)                                                     \
    CFG_ENTRY(app_layer0protocols0http20enabled)                                                   \
    CFG_ENTRY(app_layer0protocols0smtp0enabled)                                                    \
    CFG_ENTRY(app_layer0protocols0smtp0raw_extraction)                                             \
    CFG_ENTRY(app_layer0protocols0smtp0mime0decode_mime)                                           \
    CFG_ENTRY(app_layer0protocols0smtp0mime0decode_base64)                                         \
    CFG_ENTRY(app_layer0protocols0smtp0mime0decode_quoted_printable)                               \
    CFG_ENTRY(app_layer0protocols0smtp0mime0header_value_depth)                                    \
    CFG_ENTRY(app_layer0protocols0smtp0mime0extract_urls)                                          \
    CFG_ENTRY(app_layer0protocols0smtp0mime0body_md5)                                              \
    CFG_ENTRY(app_layer0protocols0smtp0inspect_tracker0content_limit)                              \
    CFG_ENTRY(app_layer0protocols0smtp0inspect_tracker0content_inspect_min_size)                   \
    CFG_ENTRY(app_layer0protocols0smtp0inspect_tracker0content_inspect_window)                     \
    CFG_ENTRY(app_layer0protocols0imap0enabled)                                                    \
    CFG_ENTRY(app_layer0protocols0smb0enabled)                                                     \
    CFG_ENTRY(app_layer0protocols0smb0detection_ports0dp)                                          \
    CFG_ENTRY(app_layer0protocols0nfs0enabled)                                                     \
    CFG_ENTRY(app_layer0protocols0tftp0enabled)                                                    \
    CFG_ENTRY(app_layer0protocols0modbus0enabled)                                                  \
    CFG_ENTRY(app_layer0protocols0modbus0detection_ports0dp)                                       \
    CFG_ENTRY(app_layer0protocols0modbus0stream_depth)                                             \
    CFG_ENTRY(app_layer0protocols0dns0tcp0enabled)                                                 \
    CFG_ENTRY(app_layer0protocols0dns0tcp0detection_ports0dp)                                      \
    CFG_ENTRY(app_layer0protocols0dns0udp0enabled)                                                 \
    CFG_ENTRY(app_layer0protocols0dns0udp0detection_ports0dp)                                      \
    CFG_ENTRY(app_layer0protocols0dnp30enabled)                                                    \
    CFG_ENTRY(app_layer0protocols0dnp30detection_ports0dp)                                         \
    CFG_ENTRY(app_layer0protocols0icap0enabled)                                                    \
    CFG_ENTRY(app_layer0protocols0enip0enabled)                                                    \
    CFG_ENTRY(app_layer0protocols0enip0detection_ports0dp)                                         \
    CFG_ENTRY(app_layer0protocols0enip0detection_ports0sp)                                         \
    CFG_ENTRY(app_layer0protocols0ntp0enabled)                                                     \
    CFG_ENTRY(app_layer0protocols0dhcp0enabled)                                                    \
    CFG_ENTRY(app_layer0protocols0sip0enabled)                                                     \
    CFG_ENTRY(app_layer0protocols0http0enabled)                                                    \
    CFG_ENTRY(app_layer0protocols0http0memcap)                                                     \
    CFG_ENTRY(app_layer0protocols0http0libhtp0default_config0request_body_limit)                   \
    CFG_ENTRY(app_layer0protocols0http0libhtp0default_config0response_body_limit)                  \
    CFG_ENTRY(app_layer0protocols0http0libhtp0default_config0request_body_minimal_inspect_size)    \
    CFG_ENTRY(app_layer0protocols0http0libhtp0default_config0request_body_inspect_window)          \
    CFG_ENTRY(app_layer0protocols0http0libhtp0default_config0response_body_minimal_inspect_size)   \
    CFG_ENTRY(app_layer0protocols0http0libhtp0default_config0response_body_inspect_window)         \
    CFG_ENTRY(app_layer0protocols0http0libhtp0default_config0response_body_decompress_layer_limit) \
    CFG_ENTRY(app_layer0protocols0http0libhtp0default_config0prune_multiplier)                     \
    CFG_ENTRY(app_layer0protocols0http0libhtp0default_config0http_body_inline)                     \
    CFG_ENTRY(app_layer0protocols0http0libhtp0default_config0double_decode_path)                   \
    CFG_ENTRY(app_layer0protocols0http0libhtp0default_config0double_decode_query)                  \
    CFG_ENTRY(app_layer0protocols0http0libhtp0default_config0path_utf8_convert_bestfit)            \
    CFG_ENTRY(app_layer0protocols0http0libhtp0default_config0personality)                          \
    CFG_ENTRY(app_layer0protocols0http0libhtp0default_config0allow_truncated_output)               \
    CFG_ENTRY(app_layer0protocols0http0libhtp0default_config0allow_wrong_cl_extraction)            \
    CFG_ENTRY(app_layer0protocols0http0libhtp0default_config0decompression_layers_limit)           \
    CFG_ENTRY(app_layer0protocols0http0libhtp0default_config0enable_chunk_non_http11)              \
    CFG_ENTRY(app_layer0protocols0http0libhtp0default_config0force_body_extraction)                \
    CFG_ENTRY(app_layer0protocols0http0libhtp0default_config0force_start_http)                     \
    CFG_ENTRY(app_layer0protocols0http0libhtp0default_config0force_strict_chunked_parse)           \
    CFG_ENTRY(app_layer0protocols0http0libhtp0default_config0loose_empty_line)                     \
    CFG_ENTRY(app_layer0protocols0http0libhtp0default_config0lzma_enabled)                         \
    CFG_ENTRY(app_layer0protocols0http0libhtp0default_config0max_res_ignored_lines)                \
    CFG_ENTRY(app_layer0protocols0http0libhtp0default_config0remove_nonprintable_chars_header)     \
    CFG_ENTRY(decoder0teredo0enabled)                                                              \
    CFG_ENTRY(decoder0vntag0enabled)                                                               \
    CFG_ENTRY(decoder0vxlan0enabled)                                                               \
    CFG_ENTRY(decoder0vxlan0ports)                                                                 \
    CFG_ENTRY(defrag0memcap)                                                                       \
    CFG_ENTRY(defrag0hash_size)                                                                    \
    CFG_ENTRY(defrag0trackers)                                                                     \
    CFG_ENTRY(defrag0max_frags)                                                                    \
    CFG_ENTRY(defrag0prealloc)                                                                     \
    CFG_ENTRY(defrag0timeout)                                                                      \
    CFG_ENTRY(detect0profile)                                                                      \
    CFG_ENTRY(detect0sgh_mpm_context)                                                              \
    CFG_ENTRY(detect0inspection_recursion_limit)                                                   \
    CFG_ENTRY(flow0memcap)                                                                         \
    CFG_ENTRY(flow0hash_size)                                                                      \
    CFG_ENTRY(flow0prealloc)                                                                       \
    CFG_ENTRY(flow0emergency_recovery)                                                             \
    CFG_ENTRY(flow0managers)                                                                       \
    CFG_ENTRY(flow0recyclers)                                                                      \
    CFG_ENTRY(flow_timeouts0default0new)                                                           \
    CFG_ENTRY(flow_timeouts0default0established)                                                   \
    CFG_ENTRY(flow_timeouts0default0closed)                                                        \
    CFG_ENTRY(flow_timeouts0default0bypassed)                                                      \
    CFG_ENTRY(flow_timeouts0default0emergency_new)                                                 \
    CFG_ENTRY(flow_timeouts0default0emergency_established)                                         \
    CFG_ENTRY(flow_timeouts0default0emergency_closed)                                              \
    CFG_ENTRY(flow_timeouts0default0emergency_bypassed)                                            \
    CFG_ENTRY(flow_timeouts0tcp0new)                                                               \
    CFG_ENTRY(flow_timeouts0tcp0established)                                                       \
    CFG_ENTRY(flow_timeouts0tcp0closed)                                                            \
    CFG_ENTRY(flow_timeouts0tcp0bypassed)                                                          \
    CFG_ENTRY(flow_timeouts0tcp0emergency_new)                                                     \
    CFG_ENTRY(flow_timeouts0tcp0emergency_established)                                             \
    CFG_ENTRY(flow_timeouts0tcp0emergency_closed)                                                  \
    CFG_ENTRY(flow_timeouts0tcp0emergency_bypassed)                                                \
    CFG_ENTRY(flow_timeouts0udp0new)                                                               \
    CFG_ENTRY(flow_timeouts0udp0established)                                                       \
    CFG_ENTRY(flow_timeouts0udp0bypassed)                                                          \
    CFG_ENTRY(flow_timeouts0udp0emergency_new)                                                     \
    CFG_ENTRY(flow_timeouts0udp0emergency_established)                                             \
    CFG_ENTRY(flow_timeouts0udp0emergency_bypassed)                                                \
    CFG_ENTRY(flow_timeouts0icmp0new)                                                              \
    CFG_ENTRY(flow_timeouts0icmp0established)                                                      \
    CFG_ENTRY(flow_timeouts0icmp0bypassed)                                                         \
    CFG_ENTRY(flow_timeouts0icmp0emergency_new)                                                    \
    CFG_ENTRY(flow_timeouts0icmp0emergency_established)                                            \
    CFG_ENTRY(flow_timeouts0icmp0emergency_bypassed)                                               \
    CFG_ENTRY(host0hmemcap)                                                                        \
    CFG_ENTRY(host0hash_size)                                                                      \
    CFG_ENTRY(host0prealloc)                                                                       \
    CFG_ENTRY(logging0default_log_level)                                                           \
    CFG_ENTRY(logging0outputs030callback0enabled)                                                  \
    CFG_ENTRY(luajit0states)                                                                       \
    CFG_ENTRY(outputs0content_snip0enabled)                                                        \
    CFG_ENTRY(outputs0content_snip0dir)                                                            \
    CFG_ENTRY(outputs0content_snip0pool_size_prealloc)                                             \
    CFG_ENTRY(outputs0content_snip0pool_size_max)                                                  \
    CFG_ENTRY(outputs0callback0enabled)                                                            \
    CFG_ENTRY(outputs0callback0alert0enabled)                                                      \
    CFG_ENTRY(outputs0callback0alert0xff0enabled)                                                  \
    CFG_ENTRY(outputs0callback0alert0xff0mode)                                                     \
    CFG_ENTRY(outputs0callback0alert0xff0deployment)                                               \
    CFG_ENTRY(outputs0callback0fileinfo0enabled)                                                   \
    CFG_ENTRY(outputs0callback0fileinfo0force_filestore)                                           \
    CFG_ENTRY(outputs0callback0fileinfo0stored_only)                                               \
    CFG_ENTRY(outputs0callback0flow0enabled)                                                       \
    CFG_ENTRY(outputs0callback0flow_snip0enabled)                                                  \
    CFG_ENTRY(outputs0callback0http0enabled)                                                       \
    CFG_ENTRY(outputs0callback0http0extended)                                                      \
    CFG_ENTRY(outputs0callback0http0xff0enabled)                                                   \
    CFG_ENTRY(outputs0callback0http0xff0mode)                                                      \
    CFG_ENTRY(outputs0callback0http0xff0deployment)                                                \
    CFG_ENTRY(outputs0callback0http0xff0header)                                                    \
    CFG_ENTRY(outputs0callback0http0dump_all_headers)                                              \
    CFG_ENTRY(outputs0callback0nta0enabled)                                                        \
    CFG_ENTRY(outputs0callback0nta0dhcp0extended)                                                  \
    CFG_ENTRY(outputs0callback0nta0dns)                                                            \
    CFG_ENTRY(outputs0callback0nta0krb5)                                                           \
    CFG_ENTRY(outputs0callback0nta0smb)                                                            \
    CFG_ENTRY(outputs0callback0nta0tls0extended)                                                   \
    CFG_ENTRY(outputs0callback0nta0tls0custom)                                                     \
    CFG_ENTRY(outputs0lua0enabled)                                                                 \
    CFG_ENTRY(outputs0lua0scripts_dir)                                                             \
    CFG_ENTRY(outputs0lua0scripts)                                                                 \
    CFG_ENTRY(outputs0file_store0version)                                                          \
    CFG_ENTRY(outputs0file_store0enabled)                                                          \
    CFG_ENTRY(outputs0file_store0dir)                                                              \
    CFG_ENTRY(outputs0file_store0force_filestore)                                                  \
    CFG_ENTRY(outputs0file_store0force_hash)                                                       \
    CFG_ENTRY(outputs0file_store0force_magic)                                                      \
    CFG_ENTRY(outputs0file_store0stream_depth)                                                     \
    CFG_ENTRY(outputs0file_store0write_fileinfo)                                                   \
    CFG_ENTRY(outputs0stats0enabled)                                                               \
    CFG_ENTRY(outputs0stats0append)                                                                \
    CFG_ENTRY(outputs0stats0totals)                                                                \
    CFG_ENTRY(outputs0stats0threads)                                                               \
    CFG_ENTRY(outputs0stats0threads_compact)                                                       \
    CFG_ENTRY(pcre0match_limit)                                                                    \
    CFG_ENTRY(pcre0match_limit_recursion)                                                          \
    CFG_ENTRY(stats0enabled)                                                                       \
    CFG_ENTRY(stats0interval)                                                                      \
    CFG_ENTRY(stream0memcap)                                                                       \
    CFG_ENTRY(stream0checksum_validation)                                                          \
    CFG_ENTRY(stream0midstream)                                                                    \
    CFG_ENTRY(stream0async_oneside)                                                                \
    CFG_ENTRY(stream0inline)                                                                       \
    CFG_ENTRY(stream0prealloc_sessions)                                                            \
    CFG_ENTRY(stream0bypass)                                                                       \
    CFG_ENTRY(stream0reassembly0memcap)                                                            \
    CFG_ENTRY(stream0reassembly0segment_prealloc)                                                  \
    CFG_ENTRY(stream0reassembly0depth)                                                             \
    CFG_ENTRY(stream0reassembly0toserver_chunk_size)                                               \
    CFG_ENTRY(stream0reassembly0toclient_chunk_size)                                               \
    CFG_ENTRY(vars0address_groups0AIM_SERVERS)                                                     \
    CFG_ENTRY(vars0address_groups0CUST_HOME_NET)                                                   \
    CFG_ENTRY(vars0address_groups0DNP3_CLIENT)                                                     \
    CFG_ENTRY(vars0address_groups0DNP3_SERVER)                                                     \
    CFG_ENTRY(vars0address_groups0DNS_SERVERS)                                                     \
    CFG_ENTRY(vars0address_groups0ENIP_CLIENT)                                                     \
    CFG_ENTRY(vars0address_groups0ENIP_SERVER)                                                     \
    CFG_ENTRY(vars0address_groups0EXTERNAL_NET)                                                    \
    CFG_ENTRY(vars0address_groups0HOME_NET)                                                        \
    CFG_ENTRY(vars0address_groups0HOME_NETWORK)                                                    \
    CFG_ENTRY(vars0address_groups0HTTP_SERVERS)                                                    \
    CFG_ENTRY(vars0address_groups0MODBUS_CLIENT)                                                   \
    CFG_ENTRY(vars0address_groups0MODBUS_SERVER)                                                   \
    CFG_ENTRY(vars0address_groups0SMTP_SERVERS)                                                    \
    CFG_ENTRY(vars0address_groups0SQL_SERVERS)                                                     \
    CFG_ENTRY(vars0address_groups0TELNET_NET)                                                      \
    CFG_ENTRY(vars0port_groups0DNP3_PORTS)                                                         \
    CFG_ENTRY(vars0port_groups0HTTP_PORTS)                                                         \
    CFG_ENTRY(vars0port_groups0ORACLE_PORTS)                                                       \
    CFG_ENTRY(vars0port_groups0SHELLCODE_ORTS)                                                     \
    CFG_ENTRY(vars0port_groups0SSH_PORTS)                                                          \
    CFG_ENTRY(vars0port_groups0VXLAN_PORTS)                                                        \
    CFG_ENTRY(vlan0use_for_tracking)

/* TODO: Add configuration entries for: CPU affinity  ? */


/* Define Suricata configuration struct. */
typedef struct SuricataCfg {
#define CFG_ENTRY(name) const char *name;
    CFG_FIELDS
#undef CFG_ENTRY
} SuricataCfg;

/**
 * \brief Retrieve the default suricata configuration (library mode).
 *
 * \return The suricata configuration.
 */
SuricataCfg CfgGetDefault(void);

/**
 * \brief Build the configuration object from yaml (library mode).
 *
 * \param filename Filename of the yaml to load.
 * \param  cfg     The SuricataCfg object.
 * \return         Error code.
 */
int CfgLoadYaml(const char *filename, SuricataCfg *cfg);

/** \brief Setup configuration from the given object.
  *
  * \param  cfg      The SuricataCfg object.
  * \return          Error code.
  */
int CfgLoadStruct(SuricataCfg *cfg);

/** \brief Set a configuration option by key.
  *
  * \param cfg       The SuricataCfg object.
  * \param key       The configuration option key.
  * \param val       The configuration option value.
  *
  * \return          1 If set, 0 if not set.
  */
int CfgSet(SuricataCfg *cfg, const char *key, const char *val);

/** \brief Free the configuration object.
  *
  * \param cfg       The SuricataCfg object.
  */
void CfgFree(SuricataCfg *cfg);

#endif /* __CONF_STRUCT_LOADER_H__ */
