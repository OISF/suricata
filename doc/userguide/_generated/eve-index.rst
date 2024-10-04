Top Level (object)
^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================== ================ ==============================
   Name               Type             Description                   
   ================== ================ ==============================
   app_proto          string                                         
   app_proto_expected string                                         
   app_proto_orig     string                                         
   app_proto_tc       string                                         
   app_proto_ts       string                                         
   capture_file       string                                         
   community_id       string                                         
   dest_ip            string                                         
   dest_port          integer                                        
   event_type         string                                         
   flow_id            integer                                        
   host               string           the sensor-name, if configured
   icmp_code          integer                                        
   icmp_type          integer                                        
   in_iface           string                                         
   log_level          string                                         
   packet             string                                         
   parent_id          integer                                        
   payload            string                                         
   payload_length     integer                                        
   payload_printable  string                                         
   pcap_cnt           integer                                        
   pcap_filename      string                                         
   pkt_src            string                                         
   proto              string                                         
   response_icmp_code integer                                        
   response_icmp_type integer                                        
   spi                integer                                        
   src_ip             string                                         
   src_port           integer                                        
   stream             integer                                        
   timestamp          string                                         
   verdict            object                                         
   direction          string                                         
   tx_id              integer                                        
   files              array of objects                               
   vlan               array of numbers                               
   alert              object                                         
   stream_tcp         object                                         
   anomaly            object                                         
   arp                object                                         
   bittorrent_dht     object                                         
   dcerpc             object                                         
   dhcp               object                                         
   dnp3               object                                         
   dns                object                                         
   drop               object                                         
   email              object                                         
   engine             object                                         
   enip               object                                         
   ether              object                                         
   fileinfo           object                                         
   flow               object                                         
   frame              object                                         
   ftp                object                                         
   ftp_data           object                                         
   http               object                                         
   ike                object                                         
   krb5               object                                         
   ldap               object                                         
   metadata           object                                         
   modbus             object                                         
   mqtt               object                                         
   netflow            object                                         
   nfs                object                                         
   packet_info        object                                         
   pgsql              object                                         
   quic               object                                         
   rdp                object                                         
   rfb                object                                         
   rpc                object                                         
   sip                object                                         
   smb                object                                         
   smtp               object                                         
   snmp               object                                         
   ssh                object                                         
   stats              object                                         
   tcp                object                                         
   template           object                                         
   tftp               object                                         
   tls                object                                         
   traffic            object                                         
   tunnel             object                                         
   websocket          object                                         
   ================== ================ ==============================

websocket (object)
^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================= ======= ===========
   Name              Type    Description
   ================= ======= ===========
   fin               boolean            
   mask              integer            
   opcode            string             
   payload_base64    string             
   payload_printable string             
   ================= ======= ===========

tunnel (object)
^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========= ======= ===========
   Name      Type    Description
   ========= ======= ===========
   depth     integer            
   dest_ip   string             
   dest_port integer            
   pcap_cnt  integer            
   pkt_src   string             
   proto     string             
   src_ip    string             
   src_port  integer            
   ========= ======= ===========

traffic (object)
^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ===== ================ ===========
   Name  Type             Description
   ===== ================ ===========
   id    array of strings            
   label array of strings            
   ===== ================ ===========

tls (object)
^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =============== ================ ==================================
   Name            Type             Description                       
   =============== ================ ==================================
   client          object                                             
   client_alpns    array of strings TLS client ALPN field(s)          
   server_alpns    array of strings TLS server ALPN field(s)          
   fingerprint     string                                             
   from_proto      string                                             
   issuerdn        string                                             
   subjectaltname  array of strings TLS Subject Alternative Name field
   notafter        string                                             
   notbefore       string                                             
   serial          string                                             
   session_resumed boolean                                            
   sni             string                                             
   subject         string                                             
   version         string                                             
   ja3             object                                             
   ja3s            object                                             
   ja4             string                                             
   =============== ================ ==================================

tls.ja3s (object)
^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====== ====== ===========
   Name   Type   Description
   ====== ====== ===========
   hash   string            
   string string            
   ====== ====== ===========

tls.ja3 (object)
^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====== ====== ===========
   Name   Type   Description
   ====== ====== ===========
   hash   string            
   string string            
   ====== ====== ===========

tls.client (object)
^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============== ================ ==================================
   Name           Type             Description                       
   ============== ================ ==================================
   fingerprint    string                                             
   issuerdn       string                                             
   subjectaltname array of strings TLS Subject Alternative Name field
   notafter       string                                             
   notbefore      string                                             
   serial         string                                             
   subject        string                                             
   ============== ================ ==================================

tftp (object)
^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====== ====== ===========
   Name   Type   Description
   ====== ====== ===========
   file   string            
   mode   string            
   packet string            
   ====== ====== ===========

template (object)
^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======== ====== ===========
   Name     Type   Description
   ======== ====== ===========
   request  string            
   response string            
   ======== ====== ===========

tcp (object)
^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============== ======= ===========
   Name           Type    Description
   ============== ======= ===========
   ack            boolean            
   cwr            boolean            
   ecn            boolean            
   fin            boolean            
   psh            boolean            
   rst            boolean            
   state          string             
   syn            boolean            
   tc_gap         boolean            
   tc_max_regions integer            
   tcp_flags      string             
   tcp_flags_tc   string             
   tcp_flags_ts   string             
   ts_gap         boolean            
   ts_max_regions integer            
   urg            boolean            
   ============== ======= ===========

stats (object)
^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============= ======= ========================
   Name          Type    Description             
   ============= ======= ========================
   uptime        integer Suricata engine's uptime
   capture       object                          
   app_layer     object                          
   ips           object                          
   decoder       object                          
   defrag        object                          
   detect        object                          
   file_store    object                          
   flow          object                          
   flow_bypassed object                          
   flow_mgr      object                          
   memcap        object                          
   ftp           object                          
   http          object                          
   tcp           object                          
   ============= ======= ========================

stats.tcp (object)
^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========================== ======= ===========
   Name                        Type    Description
   =========================== ======= ===========
   ack_unseen_data             integer            
   active_sessions             integer            
   insert_data_normal_fail     integer            
   insert_data_overlap_fail    integer            
   insert_list_fail            integer            
   invalid_checksum            integer            
   memuse                      integer            
   midstream_pickups           integer            
   midstream_exception_policy  object             
   no_flow                     integer            
   overlap                     integer            
   overlap_diff_data           integer            
   pkt_on_wrong_thread         integer            
   pseudo                      integer            
   pseudo_failed               integer            
   reassembly_exception_policy object             
   reassembly_gap              integer            
   reassembly_memuse           integer            
   rst                         integer            
   segment_memcap_drop         integer            
   segment_from_cache          integer            
   segment_from_pool           integer            
   sessions                    integer            
   ssn_from_cache              integer            
   ssn_from_pool               integer            
   ssn_memcap_drop             integer            
   ssn_memcap_exception_policy object             
   stream_depth_reached        integer            
   syn                         integer            
   synack                      integer            
   =========================== ======= ===========

stats.tcp.ssn_memcap_exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.tcp.reassembly_exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.tcp.midstream_exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.http (object)
^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====== ======= ===========
   Name   Type    Description
   ====== ======= ===========
   memcap integer            
   memuse integer            
   ====== ======= ===========

stats.ftp (object)
^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====== ======= ===========
   Name   Type    Description
   ====== ======= ===========
   memcap integer            
   memuse integer            
   ====== ======= ===========

stats.memcap (object)
^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============ ======= ================================================================================
   Name         Type    Description                                                                     
   ============ ======= ================================================================================
   pressure     integer Percentage of memcaps used by flow, stream, stream-reassembly and app-layer-http
   pressure_max integer Maximum pressure seen by the engine                                             
   ============ ======= ================================================================================

stats.flow_mgr (object)
^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =============== ======= ===========
   Name            Type    Description
   =============== ======= ===========
   bypassed_pruned integer            
   closed_pruned   integer            
   est_pruned      integer            
   flows_checked   integer            
   flows_notimeout integer            
   flows_removed   integer            
   flows_timeout   integer            
   new_pruned      integer            
   rows_busy       integer            
   rows_checked    integer            
   rows_empty      integer            
   rows_maxlen     integer            
   rows_skipped    integer            
   =============== ======= ===========

stats.flow_bypassed (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =================== ======= ===========
   Name                Type    Description
   =================== ======= ===========
   bytes               integer            
   closed              integer            
   local_bytes         integer            
   local_capture_bytes integer            
   local_capture_pkts  integer            
   local_pkts          integer            
   pkts                integer            
   =================== ======= ===========

stats.flow (object)
^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======================= ======= ===============================================================================================
   Name                    Type    Description                                                                                    
   ======================= ======= ===============================================================================================
   active                  integer Number of currently active flows                                                               
   emerg_mode_entered      integer Number of times emergency mode was entered                                                     
   emerg_mode_over         integer Number of times recovery was made from emergency mode                                          
   get_used                integer Number of reused flows from the hash table in case memcap was reached and spare pool was empty 
   get_used_eval           integer Number of attempts at getting a flow directly from the hash                                    
   get_used_eval_busy      integer Number of times a flow was found in the hash but the lock for hash bucket could not be obtained
   get_used_eval_reject    integer Number of flows that were evaluated but rejected from reuse as they were still alive/active    
   get_used_failed         integer Number of times retrieval of flow from hash was attempted but was unsuccessful                 
   icmpv4                  integer Number of ICMPv4 flows                                                                         
   icmpv6                  integer Number of ICMPv6 flows                                                                         
   memcap                  integer Number of times memcap was reached for flows                                                   
   memcap_exception_policy object                                                                                                 
   memuse                  integer Memory currently in use by the flows                                                           
   spare                   integer Number of flows in the spare pool                                                              
   tcp                     integer Number of TCP flows                                                                            
   tcp_reuse               integer Number of TCP flows that were reused as they seemed to share the same flow tuple               
   total                   integer Total number of flows                                                                          
   udp                     integer Number of UDP flows                                                                            
   end                     object                                                                                                 
   mgr                     object                                                                                                 
   recycler                object                                                                                                 
   wrk                     object                                                                                                 
   ======================= ======= ===============================================================================================

stats.flow.wrk (object)
^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======================== ======= ===========
   Name                     Type    Description
   ======================== ======= ===========
   flows_evicted            integer            
   flows_evicted_needs_work integer            
   flows_evicted_pkt_inject integer            
   flows_injected           integer            
   flows_injected_max       integer            
   spare_sync               integer            
   spare_sync_avg           integer            
   spare_sync_empty         integer            
   spare_sync_incomplete    integer            
   ======================== ======= ===========

stats.flow.recycler (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========= ======= ==========================================
   Name      Type    Description                               
   ========= ======= ==========================================
   recycled  integer number of recycled flows                  
   queue_avg integer average number of recycled flows per queue
   queue_max integer maximum number of recycled flows per queue
   ========= ======= ==========================================

stats.flow.mgr (object)
^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======================== ======= =============================================================================================================
   Name                     Type    Description                                                                                                  
   ======================== ======= =============================================================================================================
   flows_checked            integer number of flows checked for timeout in the last pass                                                         
   flows_evicted            integer number of flows that were evicted                                                                            
   flows_evicted_needs_work integer number of TCP flows that were returned to the workers in case reassembly, detection, logging still needs work
   flows_notimeout          integer number of flows that did not time out                                                                        
   flows_timeout            integer number of flows that reached the time out                                                                    
   full_hash_pass           integer number of times a full pass of the hash table was done                                                       
   rows_maxlen              integer size of the biggest row in the hash table                                                                    
   rows_per_sec             integer number of rows to be scanned every second by a worker                                                        
   ======================== ======= =============================================================================================================

stats.flow.end (object)
^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   state       object             
   tcp_state   object             
   tcp_liberal integer            
   =========== ======= ===========

stats.flow.end.tcp_state (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   none        integer            
   syn_sent    integer            
   syn_recv    integer            
   established integer            
   fin_wait1   integer            
   fin_wait2   integer            
   time_wait   integer            
   last_ack    integer            
   close_wait  integer            
   closing     integer            
   closed      integer            
   =========== ======= ===========

stats.flow.end.state (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===========
   Name             Type    Description
   ================ ======= ===========
   new              integer            
   established      integer            
   closed           integer            
   local_bypassed   integer            
   capture_bypassed integer            
   ================ ======= ===========

stats.flow.memcap_exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.file_store (object)
^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================== ======= ===========
   Name               Type    Description
   ================== ======= ===========
   fs_errors          integer            
   open_files         integer            
   open_files_max_hit integer            
   ================== ======= ===========

stats.detect (object)
^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ==================== ================ ===========
   Name                 Type             Description
   ==================== ================ ===========
   alert                integer                     
   alert_queue_overflow integer                     
   alerts_suppressed    integer                     
   lua                  object                      
   mpm_list             integer                     
   nonmpm_list          integer                     
   fnonmpm_list         integer                     
   match_list           integer                     
   engines              array of objects            
   ==================== ================ ===========

stats.detect.engines (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============= ======= ===========
   Name          Type    Description
   ============= ======= ===========
   id            integer            
   last_reload   string             
   rules_loaded  integer            
   rules_failed  integer            
   rules_skipped integer            
   ============= ======= ===========

stats.detect.lua (object)
^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======================== ======= =====================================================================
   Name                     Type    Description                                                          
   ======================== ======= =====================================================================
   blocked_function_errors  integer Counter for Lua scripts failing due to blocked functions being called
   instruction_limit_errors integer Count of Lua rules exceeding the instruction limit                   
   memory_limit_errors      integer Count of Lua rules exceeding the memory limit                        
   errors                   integer Errors encountered while running Lua scripts                         
   ======================== ======= =====================================================================

stats.defrag (object)
^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======================= ======= ==================================================================================
   Name                    Type    Description                                                                       
   ======================= ======= ==================================================================================
   tracker_soft_reuse      integer Finished tracker re-used from hash table before being moved to spare pool         
   tracker_hard_reuse      integer Active tracker force closed before completion and reused for new tracker          
   max_trackers_reached    integer How many times a packet wasn't reassembled due to max-trackers limit being reached
   max_frags_reached       integer How many times a fragment wasn't stored due to max-frags limit being reached      
   memuse                  integer Current memory use.                                                               
   memcap_exception_policy object                                                                                    
   ipv4                    object                                                                                    
   ipv6                    object                                                                                    
   mgr                     object                                                                                    
   wrk                     object                                                                                    
   ======================= ======= ==================================================================================

stats.defrag.wrk (object)
^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =============== ======= ===========
   Name            Type    Description
   =============== ======= ===========
   tracker_timeout integer            
   =============== ======= ===========

stats.defrag.mgr (object)
^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =============== ======= ===========
   Name            Type    Description
   =============== ======= ===========
   tracker_timeout integer            
   =============== ======= ===========

stats.defrag.ipv6 (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   fragments   integer            
   reassembled integer            
   timeouts    integer            
   =========== ======= ===========

stats.defrag.ipv4 (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   fragments   integer            
   reassembled integer            
   timeouts    integer            
   =========== ======= ===========

stats.defrag.memcap_exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.decoder (object)
^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================= ======= ===========
   Name              Type    Description
   ================= ======= ===========
   avg_pkt_size      integer            
   bytes             integer            
   chdlc             integer            
   erspan            integer            
   esp               integer            
   ethernet          integer            
   arp               integer            
   unknown_ethertype integer            
   geneve            integer            
   gre               integer            
   icmpv4            integer            
   icmpv6            integer            
   ieee8021ah        integer            
   invalid           integer            
   ipv4              integer            
   ipv4_in_ipv6      integer            
   ipv6              integer            
   ipv6_in_ipv6      integer            
   max_mac_addrs_dst integer            
   max_mac_addrs_src integer            
   max_pkt_size      integer            
   mpls              integer            
   nsh               integer            
   null              integer            
   pkts              integer            
   ppp               integer            
   pppoe             integer            
   raw               integer            
   sctp              integer            
   sll               integer            
   tcp               integer            
   teredo            integer            
   too_many_layers   integer            
   udp               integer            
   vlan              integer            
   vlan_qinq         integer            
   vlan_qinqinq      integer            
   vntag             integer            
   vxlan             integer            
   event             object             
   ================= ======= ===========

stats.decoder.event (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========== ====== ===========
   Name       Type   Description
   ========== ====== ===========
   arp        object            
   chdlc      object            
   dce        object            
   erspan     object            
   esp        object            
   ethernet   object            
   geneve     object            
   gre        object            
   icmpv4     object            
   icmpv6     object            
   ieee8021ah object            
   ipraw      object            
   ipv4       object            
   ipv6       object            
   ltnull     object            
   mpls       object            
   nsh        object            
   ppp        object            
   pppoe      object            
   sctp       object            
   sll        object            
   tcp        object            
   udp        object            
   vlan       object            
   vntag      object            
   vxlan      object            
   ========== ====== ===========

stats.decoder.event.vxlan (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ==================== ======= ===========
   Name                 Type    Description
   ==================== ======= ===========
   unknown_payload_type integer            
   ==================== ======= ===========

stats.decoder.event.vntag (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===========
   Name             Type    Description
   ================ ======= ===========
   header_too_small integer            
   unknown_type     integer            
   ================ ======= ===========

stats.decoder.event.vlan (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===========
   Name             Type    Description
   ================ ======= ===========
   header_too_small integer            
   too_many_layers  integer            
   unknown_type     integer            
   ================ ======= ===========

stats.decoder.event.udp (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============== ======= ===========
   Name           Type    Description
   ============== ======= ===========
   hlen_invalid   integer            
   hlen_too_small integer            
   pkt_too_small  integer            
   len_invalid    integer            
   ============== ======= ===========

stats.decoder.event.tcp (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =============== ======= ===========
   Name            Type    Description
   =============== ======= ===========
   hlen_too_small  integer            
   invalid_optlen  integer            
   opt_duplicate   integer            
   opt_invalid_len integer            
   pkt_too_small   integer            
   =============== ======= ===========

stats.decoder.event.sll (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============= ======= ===========
   Name          Type    Description
   ============= ======= ===========
   pkt_too_small integer            
   ============= ======= ===========

stats.decoder.event.sctp (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============= ======= ===========
   Name          Type    Description
   ============= ======= ===========
   pkt_too_small integer            
   ============= ======= ===========

stats.decoder.event.pppoe (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============== ======= ===========
   Name           Type    Description
   ============== ======= ===========
   malformed_tags integer            
   pkt_too_small  integer            
   wrong_code     integer            
   ============== ======= ===========

stats.decoder.event.ppp (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================= ======= ===========
   Name              Type    Description
   ================= ======= ===========
   ip4_pkt_too_small integer            
   ip6_pkt_too_small integer            
   pkt_too_small     integer            
   unsup_proto       integer            
   vju_pkt_too_small integer            
   wrong_type        integer            
   ================= ======= ===========

stats.decoder.event.nsh (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =================== ======= ===========
   Name                Type    Description
   =================== ======= ===========
   bad_header_length   integer            
   header_too_small    integer            
   reserved_type       integer            
   unknown_payload     integer            
   unsupported_type    integer            
   unsupported_version integer            
   =================== ======= ===========

stats.decoder.event.mpls (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======================= ======= ===========
   Name                    Type    Description
   ======================= ======= ===========
   bad_label_implicit_null integer            
   bad_label_reserved      integer            
   bad_label_router_alert  integer            
   header_too_small        integer            
   pkt_too_small           integer            
   unknown_payload_type    integer            
   ======================= ======= ===========

stats.decoder.event.ltnull (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===========
   Name             Type    Description
   ================ ======= ===========
   pkt_too_small    integer            
   unsupported_type integer            
   ================ ======= ===========

stats.decoder.event.ipv6 (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========================== ======= ===========
   Name                       Type    Description
   ========================== ======= ===========
   data_after_none_header     integer            
   dstopts_only_padding       integer            
   dstopts_unknown_opt        integer            
   exthdr_ah_res_not_null     integer            
   exthdr_dupl_ah             integer            
   exthdr_dupl_dh             integer            
   exthdr_dupl_eh             integer            
   exthdr_dupl_fh             integer            
   exthdr_dupl_hh             integer            
   exthdr_dupl_rh             integer            
   exthdr_invalid_optlen      integer            
   exthdr_useless_fh          integer            
   fh_non_zero_reserved_field integer            
   frag_ignored               integer            
   frag_invalid_length        integer            
   frag_overlap               integer            
   frag_pkt_too_large         integer            
   hopopts_only_padding       integer            
   hopopts_unknown_opt        integer            
   icmpv4                     integer            
   ipv4_in_ipv6_too_small     integer            
   ipv4_in_ipv6_wrong_version integer            
   ipv6_in_ipv6_too_small     integer            
   ipv6_in_ipv6_wrong_version integer            
   pkt_too_small              integer            
   rh_type_0                  integer            
   trunc_exthdr               integer            
   trunc_pkt                  integer            
   unknown_next_header        integer            
   wrong_ip_version           integer            
   zero_len_padn              integer            
   ========================== ======= ===========

stats.decoder.event.ipv4 (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======================= ======= ===========
   Name                    Type    Description
   ======================= ======= ===========
   frag_ignored            integer            
   frag_overlap            integer            
   frag_pkt_too_large      integer            
   hlen_too_small          integer            
   icmpv6                  integer            
   iplen_smaller_than_hlen integer            
   opt_duplicate           integer            
   opt_eol_required        integer            
   opt_invalid             integer            
   opt_invalid_len         integer            
   opt_malformed           integer            
   opt_pad_required        integer            
   opt_unknown             integer            
   pkt_too_small           integer            
   trunc_pkt               integer            
   wrong_ip_version        integer            
   ======================= ======= ===========

stats.decoder.event.ipraw (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================== ======= ===========
   Name               Type    Description
   ================== ======= ===========
   invalid_ip_version integer            
   ================== ======= ===========

stats.decoder.event.ieee8021ah (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===========
   Name             Type    Description
   ================ ======= ===========
   header_too_small integer            
   ================ ======= ===========

stats.decoder.event.icmpv6 (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========================== ======= ===========
   Name                        Type    Description
   =========================== ======= ===========
   experimentation_type        integer            
   ipv6_trunc_pkt              integer            
   ipv6_unknown_version        integer            
   mld_message_with_invalid_hl integer            
   pkt_too_small               integer            
   unassigned_type             integer            
   unknown_code                integer            
   unknown_type                integer            
   =========================== ======= ===========

stats.decoder.event.icmpv4 (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===========
   Name             Type    Description
   ================ ======= ===========
   ipv4_trunc_pkt   integer            
   ipv4_unknown_ver integer            
   pkt_too_small    integer            
   unknown_code     integer            
   unknown_type     integer            
   ================ ======= ===========

stats.decoder.event.gre (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========================== ======= ===========
   Name                       Type    Description
   ========================== ======= ===========
   pkt_too_small              integer            
   version0_flags             integer            
   version0_hdr_too_big       integer            
   version0_malformed_sre_hdr integer            
   version0_recur             integer            
   version1_chksum            integer            
   version1_flags             integer            
   version1_hdr_too_big       integer            
   version1_malformed_sre_hdr integer            
   version1_no_key            integer            
   version1_recur             integer            
   version1_route             integer            
   version1_ssr               integer            
   version1_wrong_protocol    integer            
   wrong_version              integer            
   ========================== ======= ===========

stats.decoder.event.geneve (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ==================== ======= ===========
   Name                 Type    Description
   ==================== ======= ===========
   unknown_payload_type integer            
   ==================== ======= ===========

stats.decoder.event.ethernet (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============= ======= ===========
   Name          Type    Description
   ============= ======= ===========
   pkt_too_small integer            
   ============= ======= ===========

stats.decoder.event.esp (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============= ======= ===========
   Name          Type    Description
   ============= ======= ===========
   pkt_too_small integer            
   ============= ======= ===========

stats.decoder.event.erspan (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ==================== ======= ===========
   Name                 Type    Description
   ==================== ======= ===========
   header_too_small     integer            
   too_many_vlan_layers integer            
   unsupported_version  integer            
   ==================== ======= ===========

stats.decoder.event.dce (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============= ======= ===========
   Name          Type    Description
   ============= ======= ===========
   pkt_too_small integer            
   ============= ======= ===========

stats.decoder.event.chdlc (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============= ======= ===========
   Name          Type    Description
   ============= ======= ===========
   pkt_too_small integer            
   ============= ======= ===========

stats.decoder.event.arp (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ===================== ======= ===========
   Name                  Type    Description
   ===================== ======= ===========
   pkt_too_small         integer            
   unsupported_hardware  integer            
   unsupported_protocol  integer            
   unsupported_pkt       integer            
   invalid_hardware_size integer            
   invalid_protocol_size integer            
   unsupported_opcode    integer            
   ===================== ======= ===========

stats.ips (object)
^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= =================================================
   Name        Type    Description                                      
   =========== ======= =================================================
   accepted    integer Number of accepted packets                       
   blocked     integer Number of blocked packets                        
   rejected    integer Number of rejected packets                       
   replaced    integer Number of replaced packets                       
   drop_reason object  Number of dropped packets, grouped by drop reason
   =========== ======= =================================================

stats.ips.drop_reason (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========================== ======= ===================================================================
   Name                       Type    Description                                                        
   ========================== ======= ===================================================================
   decode_error               integer Number of packets dropped due to decoding errors                   
   defrag_error               integer Number of packets dropped due to defragmentation errors            
   defrag_memcap              integer Number of packets dropped due to defrag memcap exception policy    
   flow_memcap                integer Number of packets dropped due to flow memcap exception policy      
   flow_drop                  integer Number of packets dropped due to dropped flows                     
   applayer_error             integer Number of packets dropped due to app-layer error exception policy  
   applayer_memcap            integer Number of packets dropped due to applayer memcap                   
   rules                      integer Number of packets dropped due to rule actions                      
   threshold_detection_filter integer Number of packets dropped due to threshold detection filter        
   stream_error               integer Number of packets dropped due to invalid TCP stream                
   stream_memcap              integer Number of packets dropped due to stream memcap exception policy    
   stream_midstream           integer Number of packets dropped due to stream midstream exception policy 
   stream_reassembly          integer Number of packets dropped due to stream reassembly exception policy
   nfq_error                  integer Number of packets dropped due to no NFQ verdict                    
   tunnel_packet_drop         integer Number of packets dropped due to inner tunnel packet being dropped 
   ========================== ======= ===================================================================

stats.app_layer (object)
^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============ ======= ===========================================
   Name         Type    Description                                
   ============ ======= ===========================================
   expectations integer Expectation (dynamic parallel flow) counter
   error        object                                             
   flow         object                                             
   tx           object                                             
   ============ ======= ===========================================

stats.app_layer.tx (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============== ======= ===================================================
   Name           Type    Description                                        
   ============== ======= ===================================================
   bittorrent-dht integer Number of transactions for BitTorrent DHT protocol 
   dcerpc_tcp     integer Number of transactions for DCERPC/TCP protocol     
   dcerpc_udp     integer Number of transactions for DCERPC/UDP protocol     
   dhcp           integer Number of transactions for DHCP                    
   dnp3           integer Number of transactions for DNP3                    
   dns_tcp        integer Number of transactions for DNS/TCP protocol        
   dns_udp        integer Number of transactions for DNS/UDP protocol        
   doh2           integer                                                    
   enip_tcp       integer Number of transactions for ENIP/TCP                
   enip_udp       integer Number of transactions for ENIP/UDP                
   ftp            integer Number of transactions for FTP                     
   ftp-data       integer Number of transactions for FTP data protocol       
   http           integer Number of transactions for HTTP                    
   http2          integer Number of transactions for HTTP/2                  
   ike            integer Number of transactions for IKE protocol            
   ikev2          integer Number of transactions for IKE v2 protocol         
   imap           integer Number of transactions for IMAP                    
   krb5_tcp       integer Number of transactions for Kerberos v5/TCP protocol
   krb5_udp       integer Number of transactions for Kerberos v5/UDP protocol
   ldap_tcp       integer Number of transactions for LDAP/TCP protocol       
   ldap_udp       integer Number of transactions for LDAP/UDP protocol       
   modbus         integer Number of transactions for Modbus protocol         
   mqtt           integer Number of transactions for MQTT protocol           
   nfs_tcp        integer Number of transactions for NFS/TCP protocol        
   nfs_udp        integer Number of transactions for NFS/UDP protocol        
   ntp            integer Number of transactions for NTP                     
   pgsql          integer Number of transactions for PostgreSQL protocol     
   pop3           integer                                                    
   quic           integer Number of transactions for QUIC protocol           
   rdp            integer Number of transactions for RDP                     
   rfb            integer Number of transactions for RFB protocol            
   sip_udp        integer Number of transactions for SIP/UDP protocol        
   sip_tcp        integer Number of transactions for SIP/TCP protocol        
   smb            integer Number of transactions for SMB protocol            
   smtp           integer Number of transactions for SMTP                    
   snmp           integer Number of transactions for SNMP                    
   ssh            integer Number of transactions for SSH protocol            
   telnet         integer Number of transactions for Telnet protocol         
   tftp           integer Number of transactions for TFTP                    
   tls            integer Number of transactions for TLS protocol            
   websocket      integer                                                    
   ============== ======= ===================================================

stats.app_layer.flow (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============== ======= ============================================
   Name           Type    Description                                 
   ============== ======= ============================================
   bittorrent-dht integer Number of flows for BitTorrent DHT protocol 
   dcerpc_tcp     integer Number of flows for DCERPC/TCP protocol     
   dcerpc_udp     integer Number of flows for DCERPC/UDP protocol     
   dhcp           integer Number of flows for DHCP                    
   dnp3           integer Number of flows for DNP3                    
   dns_tcp        integer Number of flows for DNS/TCP protocol        
   dns_udp        integer Number of flows for DNS/UDP protocol        
   doh2           integer                                             
   enip_tcp       integer Number of flows for ENIP/TCP                
   enip_udp       integer Number of flows for ENIP/UDP                
   failed_tcp     integer Number of failed flows for TCP              
   failed_udp     integer Number of failed flows for UDP              
   ftp            integer Number of flows for FTP                     
   ftp-data       integer Number of flows for FTP data protocol       
   http           integer Number of flows for HTTP                    
   http2          integer Number of flows for HTTP/2                  
   ike            integer Number of flows for IKE protocol            
   ikev2          integer Number of flows for IKE v2 protocol         
   imap           integer Number of flows for IMAP                    
   krb5_tcp       integer Number of flows for Kerberos v5/TCP protocol
   krb5_udp       integer Number of flows for Kerberos v5/UDP protocol
   ldap_tcp       integer Number of flows for LDAP/TCP protocol       
   ldap_udp       integer Number of flows LDAP/UDP protocol           
   modbus         integer Number of flows for Modbus protocol         
   mqtt           integer Number of flows for MQTT protocol           
   nfs_tcp        integer Number of flows for NFS/TCP protocol        
   nfs_udp        integer Number of flows for NFS/UDP protocol        
   ntp            integer Number of flows for NTP                     
   pgsql          integer Number of flows for PostgreSQL protocol     
   pop3           integer                                             
   quic           integer Number of flows for QUIC protocol           
   rdp            integer Number of flows for RDP                     
   rfb            integer Number of flows for RFB protocol            
   sip_udp        integer Number of flows for SIP/UDP protocol        
   sip_tcp        integer Number of flows for SIP/TCP protocol        
   smb            integer Number of flows for SMB protocol            
   smtp           integer Number of flows for SMTP                    
   snmp           integer Number of flows for SNMP                    
   ssh            integer Number of flows for SSH protocol            
   telnet         integer Number of flows for Telnet protocol         
   tftp           integer Number of flows for TFTP                    
   tls            integer Number of flows for TLS protocol            
   websocket      integer                                             
   ============== ======= ============================================

stats.app_layer.error (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ====== ===========
   Name             Type   Description
   ================ ====== ===========
   exception_policy object            
   bittorrent-dht   object            
   dcerpc_tcp       object            
   dcerpc_udp       object            
   dhcp             object            
   dnp3             object            
   dns_tcp          object            
   dns_udp          object            
   doh2             object            
   enip_tcp         object            
   enip_udp         object            
   failed_tcp       object            
   ftp              object            
   ftp-data         object            
   http             object            
   http2            object            
   ike              object            
   imap             object            
   krb5_tcp         object            
   krb5_udp         object            
   ldap_tcp         object            
   ldap_udp         object            
   modbus           object            
   mqtt             object            
   nfs_tcp          object            
   nfs_udp          object            
   ntp              object            
   pgsql            object            
   pop3             object            
   quic             object            
   rdp              object            
   rfb              object            
   sip_udp          object            
   sip_tcp          object            
   smb              object            
   smtp             object            
   snmp             object            
   ssh              object            
   telnet           object            
   tftp             object            
   tls              object            
   websocket        object            
   ================ ====== ===========

stats.app_layer.error.websocket (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.websocket.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.tls (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.tls.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.tftp (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.tftp.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.telnet (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.telnet.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.ssh (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.ssh.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.snmp (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.snmp.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.smtp (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.smtp.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.smb (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.smb.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.sip_tcp (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.sip_tcp.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.sip_udp (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.sip_udp.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.rfb (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.rfb.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.rdp (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.rdp.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.quic (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.quic.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.pop3 (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.pop3.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.pgsql (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.pgsql.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.ntp (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.ntp.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.nfs_udp (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.nfs_udp.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.nfs_tcp (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.nfs_tcp.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.mqtt (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.mqtt.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.modbus (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.modbus.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.ldap_udp (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.ldap_udp.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.ldap_tcp (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.ldap_tcp.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.krb5_udp (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.krb5_udp.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.krb5_tcp (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.krb5_tcp.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.imap (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.imap.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.ike (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.ike.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.http2 (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.http2.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.http (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.http.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.ftp-data (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.ftp-data.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.ftp (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.ftp.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.failed_tcp (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.failed_tcp.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.enip_udp (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.enip_udp.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.enip_tcp (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.enip_tcp.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.doh2 (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.doh2.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.dns_udp (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.dns_udp.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.dns_tcp (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.dns_tcp.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.dnp3 (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.dnp3.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.dhcp (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.dhcp.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.dcerpc_udp (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.dcerpc_udp.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.dcerpc_tcp (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.dcerpc_tcp.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.bittorrent-dht (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===================================
   Name             Type    Description                        
   ================ ======= ===================================
   gap              integer Number of errors processing gaps   
   alloc            integer Number of errors allocating memory 
   parser           integer Number of errors reported by parser
   internal         integer Number of internal parser errors   
   exception_policy object                                     
   ================ ======= ===================================

stats.app_layer.error.bittorrent-dht.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.app_layer.error.exception_policy (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   drop_flow   integer            
   drop_packet integer            
   pass_flow   integer            
   pass_packet integer            
   bypass      integer            
   reject      integer            
   =========== ======= ===========

stats.capture (object)
^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============== ======= ===========
   Name           Type    Description
   ============== ======= ===========
   kernel_packets integer            
   kernel_drops   integer            
   kernel_ifdrops integer            
   ============== ======= ===========

ssh (object)
^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====== ====== ===========
   Name   Type   Description
   ====== ====== ===========
   client object            
   server object            
   ====== ====== ===========

ssh.server (object)
^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ====== ===========
   Name             Type   Description
   ================ ====== ===========
   proto_version    string            
   software_version string            
   hassh            object            
   ================ ====== ===========

ssh.server.hassh (object)
^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====== ====== ===========
   Name   Type   Description
   ====== ====== ===========
   hash   string            
   string string            
   ====== ====== ===========

ssh.client (object)
^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ====== ===========
   Name             Type   Description
   ================ ====== ===========
   proto_version    string            
   software_version string            
   hassh            object            
   ================ ====== ===========

ssh.client.hassh (object)
^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====== ====== ===========
   Name   Type   Description
   ====== ====== ===========
   hash   string            
   string string            
   ====== ====== ===========

snmp (object)
^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========= ================ ===========
   Name      Type             Description
   ========= ================ ===========
   community string                      
   pdu_type  string                      
   usm       string                      
   version   integer                     
   vars      array of strings            
   ========= ================ ===========

smtp (object)
^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========= ================ ===========
   Name      Type             Description
   ========= ================ ===========
   helo      string                      
   mail_from string                      
   rcpt_to   array of strings            
   ========= ================ ===========

smb (object)
^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================= ================ ===========
   Name              Type             Description
   ================= ================ ===========
   access            string                      
   accessed          integer                     
   changed           integer                     
   client_guid       string                      
   command           string                      
   created           integer                     
   dialect           string                      
   directory         string                      
   disposition       string                      
   filename          string                      
   fuid              string                      
   function          string                      
   id                integer                     
   level_of_interest string                      
   max_read_size     integer                     
   max_write_size    integer                     
   modified          integer                     
   named_pipe        string                      
   rename            object                      
   request_done      boolean                     
   response_done     boolean                     
   server_guid       string                      
   session_id        integer                     
   set_info          object                      
   share             string                      
   share_type        string                      
   size              integer                     
   subcmd            string                      
   status            string                      
   status_code       string                      
   tree_id           integer                     
   client_dialects   array of strings            
   dcerpc            object                      
   kerberos          object                      
   ntlmssp           object                      
   request           object                      
   response          object                      
   service           object                      
   ================= ================ ===========

smb.service (object)
^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======== ====== ===========
   Name     Type   Description
   ======== ====== ===========
   request  string            
   response string            
   ======== ====== ===========

smb.response (object)
^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========= ====== ===========
   Name      Type   Description
   ========= ====== ===========
   native_lm string            
   native_os string            
   ========= ====== ===========

smb.request (object)
^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========= ====== ===========
   Name      Type   Description
   ========= ====== ===========
   native_lm string            
   native_os string            
   ========= ====== ===========

smb.ntlmssp (object)
^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======= ======= ===========
   Name    Type    Description
   ======= ======= ===========
   domain  string             
   host    string             
   user    string             
   version string             
   warning boolean            
   ======= ======= ===========

smb.kerberos (object)
^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====== ================ ===========
   Name   Type             Description
   ====== ================ ===========
   realm  string                      
   snames array of strings            
   ====== ================ ===========

smb.dcerpc (object)
^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========== ================ ===========
   Name       Type             Description
   ========== ================ ===========
   call_id    integer                     
   opnum      integer                     
   request    string                      
   response   string                      
   interfaces array of objects            
   req        object                      
   res        object                      
   ========== ================ ===========

smb.dcerpc.res (object)
^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============== ======= ===========
   Name           Type    Description
   ============== ======= ===========
   frag_cnt       integer            
   stub_data_size integer            
   ============== ======= ===========

smb.dcerpc.req (object)
^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============== ======= ===========
   Name           Type    Description
   ============== ======= ===========
   frag_cnt       integer            
   stub_data_size integer            
   ============== ======= ===========

smb.dcerpc.interfaces (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========== ======= ===========
   Name       Type    Description
   ========== ======= ===========
   ack_reason integer            
   ack_result integer            
   uuid       string             
   version    string             
   ========== ======= ===========

smb.set_info (object)
^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========== ====== ===========
   Name       Type   Description
   ========== ====== ===========
   class      string            
   info_level string            
   ========== ====== ===========

smb.rename (object)
^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ==== ====== ===========
   Name Type   Description
   ==== ====== ===========
   from string            
   to   string            
   ==== ====== ===========

sip (object)
^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============= ====== ================
   Name          Type   Description     
   ============= ====== ================
   code          string                 
   method        string                 
   reason        string                 
   request_line  string                 
   response_line string                 
   uri           string                 
   version       string                 
   sdp           object SDP message body
   ============= ====== ================

sip.sdp (object)
^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================== ================ =========================================================================
   Name               Type             Description                                                              
   ================== ================ =========================================================================
   version            integer          SDP protocol version                                                     
   origin             string           Owner of the session                                                     
   session_name       string           Session name                                                             
   session_info       string           Textual information about the session                                    
   uri                string           A pointer to additional information about the session                    
   email              string           Email address for the person responsible for the conference              
   phone_number       string           Phone number for the person responsible for the conference               
   connection_data    string           Connection data                                                          
   bandwidths         array of strings Proposed bandwidths to be used by the session or media                   
   time               string           Start and stop times for a session                                       
   repeat_time        string           Specify repeat times for a session                                       
   timezone           string           Timezone to specify adjustments for times and offsets from the base time 
   encryption_key     string           Field used to convey encryption keys if SDP is used over a secure channel
   attributes         array of strings A list of attributes to extend SDP                                       
   media_descriptions array of objects A list of media descriptions for a session                               
   ================== ================ =========================================================================

sip.sdp.media_descriptions (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =============== ================ ================================================================
   Name            Type             Description                                                     
   =============== ================ ================================================================
   media           string           Media description                                               
   media_info      string           Media information primarily intended for labelling media streams
   bandwidths      array of strings A list of bandwidth proposed for a media                        
   connection_data string           Connection data per media description                           
   attributes      array of strings A list of attributes specified for a media description          
   =============== ================ ================================================================

rpc (object)
^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========= ======= ===========
   Name      Type    Description
   ========= ======= ===========
   auth_type string             
   status    string             
   xid       integer            
   creds     object             
   ========= ======= ===========

rpc.creds (object)
^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============ ======= ===========
   Name         Type    Description
   ============ ======= ===========
   gid          integer            
   machine_name string             
   uid          integer            
   ============ ======= ===========

rfb (object)
^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======================= ======= ===========
   Name                    Type    Description
   ======================= ======= ===========
   screen_shared           boolean            
   authentication          object             
   client_protocol_version object             
   framebuffer             object             
   server_protocol_version object             
   ======================= ======= ===========

rfb.server_protocol_version (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ===== ====== ===========
   Name  Type   Description
   ===== ====== ===========
   major string            
   minor string            
   ===== ====== ===========

rfb.framebuffer (object)
^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============ ======= ===========
   Name         Type    Description
   ============ ======= ===========
   height       integer            
   name         string             
   width        integer            
   pixel_format object             
   ============ ======= ===========

rfb.framebuffer.pixel_format (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============== ======= ===========
   Name           Type    Description
   ============== ======= ===========
   big_endian     boolean            
   bits_per_pixel integer            
   blue_max       integer            
   blue_shift     integer            
   depth          integer            
   green_max      integer            
   green_shift    integer            
   red_max        integer            
   red_shift      integer            
   true_color     boolean            
   ============== ======= ===========

rfb.client_protocol_version (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ===== ====== ===========
   Name  Type   Description
   ===== ====== ===========
   major string            
   minor string            
   ===== ====== ===========

rfb.authentication (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =============== ======= ===========
   Name            Type    Description
   =============== ======= ===========
   security_result string             
   security_type   integer            
   vnc             object             
   =============== ======= ===========

rfb.authentication.vnc (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========= ====== ===========
   Name      Type   Description
   ========= ====== ===========
   challenge string            
   response  string            
   ========= ====== ===========

rdp (object)
^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========== ================ ===========
   Name       Type             Description
   ========== ================ ===========
   cookie     string                      
   event_type string                      
   tx_id      integer                     
   channels   array of strings            
   client     object                      
   ========== ================ ===========

rdp.client (object)
^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =============== ================ ===========
   Name            Type             Description
   =============== ================ ===========
   build           string                      
   client_name     string                      
   color_depth     integer                     
   desktop_height  integer                     
   desktop_width   integer                     
   function_keys   integer                     
   id              string                      
   keyboard_layout string                      
   keyboard_type   string                      
   product_id      integer                     
   version         string                      
   capabilities    array of strings            
   =============== ================ ===========

quic (object)
^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========== ================ ================================================================
   Name       Type             Description                                                     
   ========== ================ ================================================================
   cyu        array of objects ja3-like fingerprint for versions of QUIC before standardization
   extensions array of objects list of extensions in hello                                     
   ja3        object           ja3 from client, as in TLS                                      
   ja3s       object           ja3 from server, as in TLS                                      
   ja4        string                                                                           
   sni        string           Server Name Indication                                          
   ua         string           User Agent for versions of QUIC before standardization          
   version    string           Quic protocol version                                           
   ========== ================ ================================================================

quic.ja3s (object)
^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====== ====== ==========================
   Name   Type   Description               
   ====== ====== ==========================
   hash   string ja3s hex representation   
   string string ja3s string representation
   ====== ====== ==========================

quic.ja3 (object)
^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====== ====== =========================
   Name   Type   Description              
   ====== ====== =========================
   hash   string ja3 hex representation   
   string string ja3 string representation
   ====== ====== =========================

quic.extensions (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====== ================ ====================================
   Name   Type             Description                         
   ====== ================ ====================================
   name   string           human-friendly name of the extension
   type   integer          integer identifier of the extension 
   values array of strings extension values                    
   ====== ================ ====================================

quic.cyu (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====== ====== ==============================
   Name   Type   Description                   
   ====== ====== ==============================
   hash   string cyu hash hex representation   
   string string cyu hash string representation
   ====== ====== ==============================

pgsql (object)
^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======== ======= ===========
   Name     Type    Description
   ======== ======= ===========
   request  object             
   response object             
   tx_id    integer            
   ======== ======= ===========

pgsql.response (object)
^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========================== ================ ===========
   Name                        Type             Description
   =========================== ================ ===========
   authentication_md5_password string                      
   authentication_sasl_final   string                      
   code                        string                      
   command_completed           string                      
   data_rows                   integer                     
   data_size                   integer                     
   field_count                 integer                     
   file                        string                      
   line                        string                      
   message                     string                      
   parameter_status            array of objects            
   process_id                  integer                     
   routine                     string                      
   secret_key                  integer                     
   severity_localizable        string                      
   severity_non_localizable    string                      
   ssl_accepted                boolean                     
   =========================== ================ ===========

pgsql.response.parameter_status (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========================== ====== ===========
   Name                        Type   Description
   =========================== ====== ===========
   application_name            string            
   client_encoding             string            
   date_style                  string            
   integer_datetimes           string            
   interval_style              string            
   is_superuser                string            
   server_encoding             string            
   server_version              string            
   session_authorization       string            
   standard_conforming_strings string            
   time_zone                   string            
   =========================== ====== ===========

pgsql.request (object)
^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============================= ======= ===========
   Name                          Type    Description
   ============================= ======= ===========
   message                       string             
   password                      string             
   password_message              string             
   process_id                    integer            
   protocol_version              string             
   sasl_authentication_mechanism string             
   sasl_param                    string             
   sasl_response                 string             
   secret_key                    integer            
   simple_query                  string             
   startup_parameters            object             
   ============================= ======= ===========

pgsql.request.startup_parameters (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =================== ================ ===========
   Name                Type             Description
   =================== ================ ===========
   optional_parameters array of objects            
   user                string                      
   =================== ================ ===========

pgsql.request.startup_parameters.optional_parameters (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================== ====== ===========
   Name               Type   Description
   ================== ====== ===========
   application_name   string            
   client_encoding    string            
   database           string            
   datestyle          string            
   extra_float_digits string            
   options            string            
   replication        string            
   ================== ====== ===========

packet_info (object)
^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======== ======= ===========
   Name     Type    Description
   ======== ======= ===========
   linktype integer            
   ======== ======= ===========

nfs (object)
^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========= ======= ===========
   Name      Type    Description
   ========= ======= ===========
   file_tx   boolean            
   filename  string             
   hhash     string             
   id        integer            
   procedure string             
   status    string             
   type      string             
   version   integer            
   read      object             
   rename    object             
   write     object             
   ========= ======= ===========

nfs.write (object)
^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======== ======= ===========
   Name     Type    Description
   ======== ======= ===========
   chunks   integer            
   first    boolean            
   last     boolean            
   last_xid integer            
   ======== ======= ===========

nfs.rename (object)
^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ==== ====== ===========
   Name Type   Description
   ==== ====== ===========
   from string            
   to   string            
   ==== ====== ===========

nfs.read (object)
^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======== ======= ===========
   Name     Type    Description
   ======== ======= ===========
   chunks   integer            
   first    boolean            
   last     boolean            
   last_xid integer            
   ======== ======= ===========

netflow (object)
^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======= ======= ===========
   Name    Type    Description
   ======= ======= ===========
   age     integer            
   bytes   integer            
   end     string             
   max_ttl integer            
   min_ttl integer            
   pkts    integer            
   start   string             
   ======= ======= ===========

mqtt (object)
^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ====== ===========
   Name        Type   Description
   =========== ====== ===========
   connack     object            
   connect     object            
   disconnect  object            
   pingreq     object            
   pingresp    object            
   puback      object            
   pubcomp     object            
   publish     object            
   pubrec      object            
   pubrel      object            
   suback      object            
   subscribe   object            
   unsuback    object            
   unsubscribe object            
   =========== ====== ===========

mqtt.unsubscribe (object)
^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========== ================ ===========
   Name       Type             Description
   ========== ================ ===========
   dup        boolean                     
   message_id integer                     
   qos        integer                     
   retain     boolean                     
   topics     array of strings            
   ========== ================ ===========

mqtt.unsuback (object)
^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============ ================= ===========
   Name         Type              Description
   ============ ================= ===========
   dup          boolean                      
   message_id   integer                      
   qos          integer                      
   retain       boolean                      
   reason_codes array of integers            
   ============ ================= ===========

mqtt.subscribe (object)
^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========== ================ ===========
   Name       Type             Description
   ========== ================ ===========
   dup        boolean                     
   message_id integer                     
   qos        integer                     
   retain     boolean                     
   topics     array of objects            
   ========== ================ ===========

mqtt.subscribe.topics (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ===== ======= ===========
   Name  Type    Description
   ===== ======= ===========
   qos   integer            
   topic string             
   ===== ======= ===========

mqtt.suback (object)
^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ================= ===========
   Name        Type              Description
   =========== ================= ===========
   dup         boolean                      
   message_id  integer                      
   qos         integer                      
   retain      boolean                      
   qos_granted array of integers            
   =========== ================= ===========

mqtt.pubrel (object)
^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   dup         boolean            
   message_id  integer            
   qos         integer            
   reason_code integer            
   retain      boolean            
   =========== ======= ===========

mqtt.pubrec (object)
^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   dup         boolean            
   message_id  integer            
   qos         integer            
   reason_code integer            
   retain      boolean            
   =========== ======= ===========

mqtt.publish (object)
^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============== ======= ===========
   Name           Type    Description
   ============== ======= ===========
   dup            boolean            
   message        string             
   message_id     integer            
   qos            integer            
   retain         boolean            
   skipped_length integer            
   topic          string             
   truncated      boolean            
   properties     object             
   ============== ======= ===========

mqtt.pubcomp (object)
^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   dup         boolean            
   message_id  integer            
   qos         integer            
   reason_code integer            
   retain      boolean            
   =========== ======= ===========

mqtt.puback (object)
^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   dup         boolean            
   message_id  integer            
   qos         integer            
   reason_code integer            
   retain      boolean            
   =========== ======= ===========

mqtt.pingresp (object)
^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====== ======= ===========
   Name   Type    Description
   ====== ======= ===========
   dup    boolean            
   qos    integer            
   retain boolean            
   ====== ======= ===========

mqtt.pingreq (object)
^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====== ======= ===========
   Name   Type    Description
   ====== ======= ===========
   dup    boolean            
   qos    integer            
   retain boolean            
   ====== ======= ===========

mqtt.disconnect (object)
^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   dup         boolean            
   qos         integer            
   reason_code integer            
   retain      boolean            
   properties  object             
   =========== ======= ===========

mqtt.connect (object)
^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===========
   Name             Type    Description
   ================ ======= ===========
   client_id        string             
   dup              boolean            
   password         string             
   protocol_string  string             
   protocol_version integer            
   qos              integer            
   retain           boolean            
   username         string             
   flags            object             
   properties       object             
   will             object             
   ================ ======= ===========

mqtt.connect.will (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========== ====== ===========
   Name       Type   Description
   ========== ====== ===========
   message    string            
   topic      string            
   properties object            
   ========== ====== ===========

mqtt.connect.flags (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============= ======= ===========
   Name          Type    Description
   ============= ======= ===========
   clean_session boolean            
   password      boolean            
   username      boolean            
   will          boolean            
   will_retain   boolean            
   ============= ======= ===========

mqtt.connack (object)
^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =============== ======= ===========
   Name            Type    Description
   =============== ======= ===========
   dup             boolean            
   qos             integer            
   retain          boolean            
   return_code     integer            
   session_present boolean            
   properties      object             
   =============== ======= ===========

modbus (object)
^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======== ======= ===========
   Name     Type    Description
   ======== ======= ===========
   id       integer            
   request  object             
   response object             
   ======== ======= ===========

modbus.response (object)
^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============== ======= ===========
   Name           Type    Description
   ============== ======= ===========
   access_type    string             
   category       string             
   data           string             
   error_flags    string             
   function_code  string             
   function_raw   integer            
   protocol_id    integer            
   transaction_id integer            
   unit_id        integer            
   diagnostic     object             
   exception      object             
   read           object             
   write          object             
   ============== ======= ===========

modbus.response.write (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======= ======= ===========
   Name    Type    Description
   ======= ======= ===========
   address integer            
   data    integer            
   ======= ======= ===========

modbus.response.read (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ==== ====== ===========
   Name Type   Description
   ==== ====== ===========
   data string            
   ==== ====== ===========

modbus.response.exception (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ==== ======= ===========
   Name Type    Description
   ==== ======= ===========
   code string             
   raw  integer            
   ==== ======= ===========

modbus.response.diagnostic (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ==== ======= ===========
   Name Type    Description
   ==== ======= ===========
   code string             
   data string             
   raw  integer            
   ==== ======= ===========

modbus.request (object)
^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============== ======= ===========
   Name           Type    Description
   ============== ======= ===========
   access_type    string             
   category       string             
   data           string             
   error_flags    string             
   function_code  string             
   function_raw   integer            
   protocol_id    integer            
   transaction_id integer            
   unit_id        integer            
   diagnostic     object             
   mei            object             
   read           object             
   write          object             
   ============== ======= ===========

modbus.request.write (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======= ======= ===========
   Name    Type    Description
   ======= ======= ===========
   address integer            
   data    integer            
   ======= ======= ===========

modbus.request.read (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======== ======= ===========
   Name     Type    Description
   ======== ======= ===========
   address  integer            
   quantity integer            
   ======== ======= ===========

modbus.request.mei (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ==== ======= ===========
   Name Type    Description
   ==== ======= ===========
   code string             
   data string             
   raw  integer            
   ==== ======= ===========

modbus.request.diagnostic (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ==== ======= ===========
   Name Type    Description
   ==== ======= ===========
   code string             
   data string             
   raw  integer            
   ==== ======= ===========

metadata (object)
^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======== ================ ===========
   Name     Type             Description
   ======== ================ ===========
   flowbits array of strings            
   flowvars array of objects            
   pktvars  array of objects            
   flowints object                      
   ======== ================ ===========

metadata.pktvars (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======== ====== ===========
   Name     Type   Description
   ======== ====== ===========
   uid      string            
   username string            
   ======== ====== ===========

metadata.flowvars (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ===== ====== ===========
   Name  Type   Description
   ===== ====== ===========
   gid   string            
   key   string            
   value string            
   ===== ====== ===========

ldap (object)
^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========= ================ ===========
   Name      Type             Description
   ========= ================ ===========
   request   object                      
   responses array of objects            
   ========= ================ ===========

ldap.responses (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ===================== ====== ===========
   Name                  Type   Description
   ===================== ====== ===========
   search_result_done    object            
   bind_response         object            
   modify_response       object            
   add_response          object            
   del_response          object            
   mod_dn_response       object            
   compare_response      object            
   extended_response     object            
   intermediate_response object            
   ===================== ====== ===========

ldap.responses.intermediate_response (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ===== ====== ===========
   Name  Type   Description
   ===== ====== ===========
   name  string            
   value string            
   ===== ====== ===========

ldap.responses.extended_response (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ====== ===========
   Name        Type   Description
   =========== ====== ===========
   result_code string            
   matched_dn  string            
   message     string            
   name        string            
   value       string            
   =========== ====== ===========

ldap.responses.compare_response (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ====== ===========
   Name        Type   Description
   =========== ====== ===========
   result_code string            
   matched_dn  string            
   message     string            
   =========== ====== ===========

ldap.responses.mod_dn_response (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ====== ===========
   Name        Type   Description
   =========== ====== ===========
   result_code string            
   matched_dn  string            
   message     string            
   =========== ====== ===========

ldap.responses.del_response (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ====== ===========
   Name        Type   Description
   =========== ====== ===========
   result_code string            
   matched_dn  string            
   message     string            
   =========== ====== ===========

ldap.responses.add_response (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ====== ===========
   Name        Type   Description
   =========== ====== ===========
   result_code string            
   matched_dn  string            
   message     string            
   =========== ====== ===========

ldap.responses.modify_response (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ====== ===========
   Name        Type   Description
   =========== ====== ===========
   result_code string            
   matched_dn  string            
   message     string            
   =========== ====== ===========

ldap.responses.bind_response (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================= ====== ===========
   Name              Type   Description
   ================= ====== ===========
   result_code       string            
   matched_dn        string            
   message           string            
   server_sasl_creds string            
   ================= ====== ===========

ldap.responses.search_result_done (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ====== ===========
   Name        Type   Description
   =========== ====== ===========
   result_code string            
   matched_dn  string            
   message     string            
   =========== ====== ===========

ldap.request (object)
^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===========
   Name             Type    Description
   ================ ======= ===========
   operation        string             
   message_id       integer            
   search_request   object             
   bind_request     object             
   modify_request   object             
   add_request      object             
   del_request      object             
   mod_dn_request   object             
   compare_request  object             
   abandon_request  object             
   extended_request object             
   ================ ======= ===========

ldap.request.extended_request (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ===== ====== ===========
   Name  Type   Description
   ===== ====== ===========
   name  string            
   value string            
   ===== ====== ===========

ldap.request.abandon_request (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========== ======= ===========
   Name       Type    Description
   ========== ======= ===========
   message_id integer            
   ========== ======= ===========

ldap.request.compare_request (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========================= ====== ===========
   Name                      Type   Description
   ========================= ====== ===========
   entry                     string            
   attribute_value_assertion object            
   ========================= ====== ===========

ldap.request.compare_request.attribute_value_assertion (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ====== ===========
   Name        Type   Description
   =========== ====== ===========
   description string            
   value       string            
   =========== ====== ===========

ldap.request.mod_dn_request (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============== ======= ===========
   Name           Type    Description
   ============== ======= ===========
   entry          string             
   new_rdn        string             
   delete_old_rdn boolean            
   new_superior   string             
   ============== ======= ===========

ldap.request.del_request (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ==== ====== ===========
   Name Type   Description
   ==== ====== ===========
   dn   string            
   ==== ====== ===========

ldap.request.add_request (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========== ================ ===========
   Name       Type             Description
   ========== ================ ===========
   entry      string                      
   attributes array of objects            
   ========== ================ ===========

ldap.request.add_request.attributes (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====== ================ ===========
   Name   Type             Description
   ====== ================ ===========
   name   string                      
   values array of strings            
   ====== ================ ===========

ldap.request.modify_request (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======= ================ ===========
   Name    Type             Description
   ======= ================ ===========
   object  string                      
   changes array of objects            
   ======= ================ ===========

ldap.request.modify_request.changes (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============ ====== ===========
   Name         Type   Description
   ============ ====== ===========
   operation    string            
   modification object            
   ============ ====== ===========

ldap.request.modify_request.changes.modification (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ================ ===========
   Name             Type             Description
   ================ ================ ===========
   attribute_type   string                      
   attribute_values array of strings            
   ================ ================ ===========

ldap.request.bind_request (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======= ======= ===========
   Name    Type    Description
   ======= ======= ===========
   version integer            
   name    string             
   sasl    object             
   ======= ======= ===========

ldap.request.bind_request.sasl (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ====== ===========
   Name        Type   Description
   =========== ====== ===========
   mechanism   string            
   credentials string            
   =========== ====== ===========

ldap.request.search_request (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============ ================ ===========
   Name         Type             Description
   ============ ================ ===========
   base_object  string                      
   scope        integer                     
   deref_alias  integer                     
   size_limit   integer                     
   time_limit   integer                     
   types_online boolean                     
   attributes   array of strings            
   ============ ================ ===========

krb5 (object)
^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====================== ======= ===========
   Name                   Type    Description
   ====================== ======= ===========
   cname                  string             
   encryption             string             
   error_code             string             
   failed_request         string             
   msg_type               string             
   realm                  string             
   sname                  string             
   ticket_encryption      string             
   ticket_weak_encryption boolean            
   weak_encryption        boolean            
   ====================== ======= ===========

ike (object)
^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ===================== ================ ===========
   Name                  Type             Description
   ===================== ================ ===========
   alg_auth              string                      
   alg_auth_raw          integer                     
   alg_dh                string                      
   alg_dh_raw            integer                     
   alg_enc               string                      
   alg_enc_raw           integer                     
   alg_hash              string                      
   alg_hash_raw          integer                     
   exchange_type         integer                     
   exchange_type_verbose string                      
   init_spi              string                      
   message_id            integer                     
   resp_spi              string                      
   role                  string                      
   sa_key_length         string                      
   sa_key_length_raw     integer                     
   sa_life_duration      string                      
   sa_life_duration_raw  integer                     
   sa_life_type          string                      
   sa_life_type_raw      integer                     
   version_major         integer                     
   version_minor         integer                     
   payload               array of strings            
   ikev1                 object                      
   ikev2                 object                      
   ===================== ================ ===========

ike.ikev2 (object)
^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====== ================= ===========
   Name   Type              Description
   ====== ================= ===========
   errors integer                      
   notify array of unknowns            
   ====== ================= ===========

ike.ikev1 (object)
^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================== ================ ===========
   Name               Type             Description
   ================== ================ ===========
   doi                integer                     
   encrypted_payloads boolean                     
   vendor_ids         array of strings            
   client             object                      
   server             object                      
   ================== ================ ===========

ike.ikev1.server (object)
^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========================== ======= ===========
   Name                        Type    Description
   =========================== ======= ===========
   key_exchange_payload        string             
   key_exchange_payload_length integer            
   nonce_payload               string             
   nonce_payload_length        integer            
   =========================== ======= ===========

ike.ikev1.client (object)
^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========================== ================ ===========
   Name                        Type             Description
   =========================== ================ ===========
   key_exchange_payload        string                      
   key_exchange_payload_length integer                     
   nonce_payload               string                      
   nonce_payload_length        integer                     
   proposals                   array of objects            
   =========================== ================ ===========

ike.ikev1.client.proposals (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ==================== ======= ===========
   Name                 Type    Description
   ==================== ======= ===========
   alg_auth             string             
   alg_auth_raw         integer            
   alg_dh               string             
   alg_dh_raw           integer            
   alg_enc              string             
   alg_enc_raw          integer            
   alg_hash             string             
   alg_hash_raw         integer            
   sa_key_length        string             
   sa_key_length_raw    integer            
   sa_life_duration     string             
   sa_life_duration_raw integer            
   sa_life_type         string             
   sa_life_type_raw     integer            
   ==================== ======= ===========

http (object)
^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============================ ================ ===========
   Name                         Type             Description
   ============================ ================ ===========
   hostname                     string                      
   http_content_type            string                      
   http_method                  string                      
   http_port                    integer                     
   http_refer                   string                      
   http_response_body           string                      
   http_response_body_printable string                      
   http_user_agent              string                      
   length                       integer                     
   org_src_ip                   string                      
   protocol                     string                      
   redirect                     string                      
   status                       integer                     
   true_client_ip               string                      
   url                          string                      
   version                      string                      
   x_bluecoat_via               string                      
   xff                          string                      
   request_headers              array of objects            
   response_headers             array of objects            
   content_range                object                      
   http2                        object                      
   ============================ ================ ===========

http.http2 (object)
^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========= ======= ===========
   Name      Type    Description
   ========= ======= ===========
   stream_id integer            
   request   object             
   response  object             
   ========= ======= ===========

http.http2.response (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========== ================ ===========
   Name       Type             Description
   ========== ================ ===========
   error_code string                      
   settings   array of objects            
   ========== ================ ===========

http.http2.response.settings (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============== ======= ===========
   Name           Type    Description
   ============== ======= ===========
   settings_id    string             
   settings_value integer            
   ============== ======= ===========

http.http2.request (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========== ================ ===========
   Name       Type             Description
   ========== ================ ===========
   error_code string                      
   priority   integer                     
   settings   array of objects            
   ========== ================ ===========

http.http2.request.settings (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============== ======= ===========
   Name           Type    Description
   ============== ======= ===========
   settings_id    string             
   settings_value integer            
   ============== ======= ===========

http.content_range (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ===== ======= ===========
   Name  Type    Description
   ===== ======= ===========
   end   integer            
   raw   string             
   size  integer            
   start integer            
   ===== ======= ===========

http.response_headers (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================= ======= ===========
   Name              Type    Description
   ================= ======= ===========
   name              string             
   table_size_update integer            
   value             string             
   ================= ======= ===========

http.request_headers (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================= ======= ===========
   Name              Type    Description
   ================= ======= ===========
   name              string             
   table_size_update integer            
   value             string             
   ================= ======= ===========

ftp_data (object)
^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======== ====== ===========
   Name     Type   Description
   ======== ====== ===========
   command  string            
   filename string            
   ======== ====== ===========

ftp (object)
^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================= ================ ===========
   Name              Type             Description
   ================= ================ ===========
   command           string                      
   command_data      string                      
   command_truncated boolean                     
   dynamic_port      integer                     
   mode              string                      
   reply_received    string                      
   reply_truncated   boolean                     
   completion_code   array of strings            
   reply             array of strings            
   ================= ================ ===========

frame (object)
^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================= ======= ===========
   Name              Type    Description
   ================= ======= ===========
   type              string             
   id                integer            
   direction         string             
   stream_offset     integer            
   length            integer            
   complete          boolean            
   payload           string             
   payload_printable string             
   tx_id             integer            
   ================= ======= ===========

flow (object)
^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============== ======= ===========
   Name           Type    Description
   ============== ======= ===========
   action         string             
   age            integer            
   alerted        boolean            
   bypass         string             
   bypassed       object             
   bytes_toclient integer            
   bytes_toserver integer            
   dest_ip        string             
   dest_port      integer            
   emergency      boolean            
   end            string             
   pkts_toclient  integer            
   pkts_toserver  integer            
   reason         string             
   src_ip         string             
   src_port       integer            
   start          string             
   state          string             
   wrong_thread   boolean            
   ============== ======= ===========

flow.bypassed (object)
^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============== ======= ===========
   Name           Type    Description
   ============== ======= ===========
   pkts_toserver  integer            
   pkts_toclient  integer            
   bytes_toserver integer            
   bytes_toclient integer            
   ============== ======= ===========

fileinfo (object)
^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======== ================= ===========================================
   Name     Type              Description                                
   ======== ================= ===========================================
   end      integer                                                      
   file_id  integer                                                      
   filename string                                                       
   gaps     boolean                                                      
   magic    string                                                       
   md5      string                                                       
   sha1     string                                                       
   sha256   string                                                       
   size     integer                                                      
   start    integer                                                      
   state    string                                                       
   stored   boolean                                                      
   storing  boolean           the file is set to be stored when completed
   tx_id    integer                                                      
   sid      array of integers                                            
   ======== ================= ===========================================

ether (object)
^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========= ================ ===========
   Name      Type             Description
   ========= ================ ===========
   dest_mac  string                      
   src_mac   string                      
   dest_macs array of strings            
   src_macs  array of strings            
   ========= ================ ===========

enip (object)
^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======== ====== ===========
   Name     Type   Description
   ======== ====== ===========
   request  object            
   response object            
   ======== ====== ===========

enip.response (object)
^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ====== ===========
   Name             Type   Description
   ================ ====== ===========
   command          string            
   status           string            
   register_session object            
   list_services    object            
   identity         object            
   cip              object            
   ================ ====== ===========

enip.response.cip (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======================= ================ ===========
   Name                    Type             Description
   ======================= ================ ===========
   service                 string                      
   status                  string                      
   status_extended         string                      
   status_extended_meaning string                      
   multiple                array of objects            
   ======================= ================ ===========

enip.response.cip.multiple (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======================= ====== ===========
   Name                    Type   Description
   ======================= ====== ===========
   service                 string            
   status                  string            
   status_extended         string            
   status_extended_meaning string            
   ======================= ====== ===========

enip.response.identity (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===========
   Name             Type    Description
   ================ ======= ===========
   protocol_version integer            
   revision         string             
   vendor_id        string             
   device_type      string             
   product_code     integer            
   status           integer            
   serial           integer            
   product_name     string             
   state            integer            
   ================ ======= ===========

enip.response.list_services (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===========
   Name             Type    Description
   ================ ======= ===========
   protocol_version integer            
   capabilities     integer            
   service_name     string             
   ================ ======= ===========

enip.response.register_session (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===========
   Name             Type    Description
   ================ ======= ===========
   protocol_version integer            
   options          integer            
   ================ ======= ===========

enip.request (object)
^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ====== ===========
   Name             Type   Description
   ================ ====== ===========
   command          string            
   status           string            
   register_session object            
   cip              object            
   ================ ====== ===========

enip.request.cip (object)
^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========== ================ ===========
   Name       Type             Description
   ========== ================ ===========
   service    string                      
   path       array of objects            
   class_name string                      
   multiple   array of objects            
   ========== ================ ===========

enip.request.cip.multiple (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========== ================ ===========
   Name       Type             Description
   ========== ================ ===========
   service    string                      
   path       array of objects            
   class_name string                      
   ========== ================ ===========

enip.request.cip.multiple.path (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============ ======= ===========
   Name         Type    Description
   ============ ======= ===========
   segment_type string             
   value        integer            
   ============ ======= ===========

enip.request.cip.path (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============ ======= ===========
   Name         Type    Description
   ============ ======= ===========
   segment_type string             
   value        integer            
   ============ ======= ===========

enip.request.register_session (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================ ======= ===========
   Name             Type    Description
   ================ ======= ===========
   protocol_version integer            
   options          integer            
   ================ ======= ===========

engine (object)
^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   error       string             
   error_code  integer            
   message     string             
   thread_name string             
   module      string             
   =========== ======= ===========

email (object)
^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============ ================ ===========
   Name         Type             Description
   ============ ================ ===========
   body_md5     string                      
   cc           array of strings            
   date         string                      
   from         string                      
   has_exe_url  boolean                     
   has_ipv4_url boolean                     
   has_ipv6_url boolean                     
   received     array of strings            
   status       string                      
   subject      string                      
   subject_md5  string                      
   to           array of strings            
   url          array of strings            
   x_mailer     string                      
   attachment   array of strings            
   message_id   string                      
   ============ ================ ===========

drop (object)
^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======== ======= ===========
   Name     Type    Description
   ======== ======= ===========
   ack      boolean            
   fin      boolean            
   flowlbl  integer            
   hoplimit integer            
   tc       integer            
   icmp_id  integer            
   icmp_seq integer            
   ipid     integer            
   len      integer            
   psh      boolean            
   rst      boolean            
   syn      boolean            
   tcpack   integer            
   tcpres   integer            
   tcpseq   integer            
   tcpurgp  integer            
   tcpwin   integer            
   tos      integer            
   ttl      integer            
   udplen   integer            
   urg      boolean            
   reason   string             
   verdict  object             
   ======== ======= ===========

drop.verdict (object)
^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============= ================ ===========
   Name          Type             Description
   ============= ================ ===========
   action        string                      
   reject        array of strings            
   reject-target string                      
   ============= ================ ===========

dns (object)
^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ================ =================================
   Name        Type             Description                      
   =========== ================ =================================
   aa          boolean                                           
   flags       string                                            
   id          integer                                           
   qr          boolean                                           
   ra          boolean                                           
   rcode       string                                            
   rd          boolean                                           
   rrname      string                                            
   rrtype      string                                            
   tx_id       integer                                           
   type        string                                            
   version     integer          The version of this EVE DNS event
   opcode      integer          DNS opcode as an integer         
   tc          boolean          DNS truncation flag              
   answers     array of objects                                  
   authorities array of objects                                  
   additionals array of objects                                  
   query       array of objects                                  
   queries     array of objects                                  
   answer      object                                            
   grouped     object                                            
   z           boolean                                           
   =========== ================ =================================

dns.grouped (object)
^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ===== ================= ======================================================================
   Name  Type              Description                                                           
   ===== ================= ======================================================================
   A     array of strings                                                                        
   AAAA  array of strings                                                                        
   CNAME array of strings                                                                        
   MX    array of strings                                                                        
   NS    array of strings                                                                        
   NULL  array of strings                                                                        
   PTR   array of strings                                                                        
   SOA   array of unknowns                                                                       
   SRV   array of objects                                                                        
   TXT   array of strings                                                                        
   SSHFP array of objects  A Secure Shell fingerprint is used to verify the system’s authenticity
   ===== ================= ======================================================================

dns.grouped.SSHFP (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   fingerprint string             
   algo        integer            
   type        integer            
   =========== ======= ===========

dns.grouped.SRV (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======== ======= ===========
   Name     Type    Description
   ======== ======= ===========
   name     string             
   port     integer            
   priority integer            
   weight   integer            
   ======== ======= ===========

dns.answer (object)
^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ================ ========================
   Name        Type             Description             
   =========== ================ ========================
   flags       string                                   
   id          integer                                  
   qr          boolean                                  
   ra          boolean                                  
   rcode       string                                   
   rd          boolean                                  
   rrname      string                                   
   rrtype      string                                   
   type        string                                   
   version     integer                                  
   opcode      integer          DNS opcode as an integer
   authorities array of objects                         
   additionals array of objects                         
   =========== ================ ========================

dns.answer.additionals (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====== ================ ===========
   Name   Type             Description
   ====== ================ ===========
   rdata  string                      
   rrname string                      
   rrtype string                      
   ttl    integer                     
   opt    array of objects            
   ====== ================ ===========

dns.answer.additionals.opt (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ==== ======= ===========
   Name Type    Description
   ==== ======= ===========
   code integer            
   data string             
   ==== ======= ===========

dns.answer.authorities (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====== ======= ===========
   Name   Type    Description
   ====== ======= ===========
   rdata  string             
   rrname string             
   rrtype string             
   ttl    integer            
   soa    object             
   ====== ======= ===========

dns.answer.authorities.soa (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======= ======= ===========
   Name    Type    Description
   ======= ======= ===========
   expire  integer            
   minimum integer            
   mname   string             
   refresh integer            
   retry   integer            
   rname   string             
   serial  integer            
   ======= ======= ===========

dns.queries (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====== ======= ========================
   Name   Type    Description             
   ====== ======= ========================
   id     integer                         
   rrname string                          
   rrtype string                          
   tx_id  integer                         
   type   string                          
   z      boolean                         
   opcode integer DNS opcode as an integer
   ====== ======= ========================

dns.query (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====== ======= ========================
   Name   Type    Description             
   ====== ======= ========================
   id     integer                         
   rrname string                          
   rrtype string                          
   tx_id  integer                         
   type   string                          
   z      boolean                         
   opcode integer DNS opcode as an integer
   ====== ======= ========================

dns.additionals (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====== ================ ===========
   Name   Type             Description
   ====== ================ ===========
   rdata  string                      
   rrname string                      
   rrtype string                      
   ttl    integer                     
   opt    array of objects            
   ====== ================ ===========

dns.additionals.opt (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ==== ======= ===========
   Name Type    Description
   ==== ======= ===========
   code integer            
   data string             
   ==== ======= ===========

dns.authorities (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====== ======= ===========
   Name   Type    Description
   ====== ======= ===========
   rdata  string             
   rrname string             
   rrtype string             
   ttl    integer            
   soa    object             
   ====== ======= ===========

dns.authorities.soa (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======= ======= ===========
   Name    Type    Description
   ======= ======= ===========
   expire  integer            
   minimum integer            
   mname   string             
   refresh integer            
   retry   integer            
   rname   string             
   serial  integer            
   ======= ======= ===========

dns.answers (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====== ======= ====================================================================
   Name   Type    Description                                                         
   ====== ======= ====================================================================
   rdata  string                                                                      
   rrname string                                                                      
   rrtype string                                                                      
   ttl    integer                                                                     
   soa    object                                                                      
   srv    object                                                                      
   sshfp  object  A Secure Shell fingerprint, used to verify the system’s authenticity
   ====== ======= ====================================================================

dns.answers.sshfp (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   fingerprint string             
   algo        integer            
   type        integer            
   =========== ======= ===========

dns.answers.srv (object)
^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======== ======= ===========
   Name     Type    Description
   ======== ======= ===========
   name     string             
   port     integer            
   priority integer            
   weight   integer            
   ======== ======= ===========

dns.answers.soa (object)
^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======= ======= ===========
   Name    Type    Description
   ======= ======= ===========
   expire  integer            
   minimum integer            
   mname   string             
   refresh integer            
   retry   integer            
   rname   string             
   serial  integer            
   ======= ======= ===========

dnp3 (object)
^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   dst         integer            
   src         integer            
   type        string             
   application object             
   control     object             
   iin         object             
   request     object             
   response    object             
   =========== ======= ===========

dnp3.response (object)
^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   dst         integer            
   src         integer            
   type        string             
   application object             
   control     object             
   iin         object             
   =========== ======= ===========

dnp3.response.iin (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========== ================ ===========
   Name       Type             Description
   ========== ================ ===========
   indicators array of strings            
   ========== ================ ===========

dnp3.response.control (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============= ======= ===========
   Name          Type    Description
   ============= ======= ===========
   dir           boolean            
   fcb           boolean            
   fcv           boolean            
   function_code integer            
   pri           boolean            
   ============= ======= ===========

dnp3.response.application (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============= ================ ===========
   Name          Type             Description
   ============= ================ ===========
   complete      boolean                     
   function_code integer                     
   objects       array of objects            
   control       object                      
   ============= ================ ===========

dnp3.response.application.control (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======== ======= ===========
   Name     Type    Description
   ======== ======= ===========
   con      boolean            
   fin      boolean            
   fir      boolean            
   sequence integer            
   uns      boolean            
   ======== ======= ===========

dnp3.response.application.objects (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ================ ===========
   Name        Type             Description
   =========== ================ ===========
   count       integer                     
   group       integer                     
   prefix_code integer                     
   qualifier   integer                     
   range_code  integer                     
   start       integer                     
   stop        integer                     
   variation   integer                     
   points      array of objects            
   =========== ================ ===========

dnp3.request (object)
^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ======= ===========
   Name        Type    Description
   =========== ======= ===========
   dst         integer            
   src         integer            
   type        string             
   application object             
   control     object             
   =========== ======= ===========

dnp3.request.control (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============= ======= ===========
   Name          Type    Description
   ============= ======= ===========
   dir           boolean            
   fcb           boolean            
   fcv           boolean            
   function_code integer            
   pri           boolean            
   ============= ======= ===========

dnp3.request.application (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============= ================ ===========
   Name          Type             Description
   ============= ================ ===========
   complete      boolean                     
   function_code integer                     
   objects       array of objects            
   control       object                      
   ============= ================ ===========

dnp3.request.application.control (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======== ======= ===========
   Name     Type    Description
   ======== ======= ===========
   con      boolean            
   fin      boolean            
   fir      boolean            
   sequence integer            
   uns      boolean            
   ======== ======= ===========

dnp3.request.application.objects (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ================ ===========
   Name        Type             Description
   =========== ================ ===========
   count       integer                     
   group       integer                     
   prefix_code integer                     
   qualifier   integer                     
   range_code  integer                     
   start       integer                     
   stop        integer                     
   variation   integer                     
   points      array of objects            
   =========== ================ ===========

dnp3.iin (object)
^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========== ================ ===========
   Name       Type             Description
   ========== ================ ===========
   indicators array of strings            
   ========== ================ ===========

dnp3.control (object)
^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============= ======= ===========
   Name          Type    Description
   ============= ======= ===========
   dir           boolean            
   fcb           boolean            
   fcv           boolean            
   function_code integer            
   pri           boolean            
   ============= ======= ===========

dnp3.application (object)
^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============= ================ ===========
   Name          Type             Description
   ============= ================ ===========
   complete      boolean                     
   function_code integer                     
   objects       array of objects            
   control       object                      
   ============= ================ ===========

dnp3.application.control (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======== ======= ===========
   Name     Type    Description
   ======== ======= ===========
   con      boolean            
   fin      boolean            
   fir      boolean            
   sequence integer            
   uns      boolean            
   ======== ======= ===========

dnp3.application.objects (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   =========== ================ ===========
   Name        Type             Description
   =========== ================ ===========
   count       integer                     
   group       integer                     
   prefix_code integer                     
   qualifier   integer                     
   range_code  integer                     
   start       integer                     
   stop        integer                     
   variation   integer                     
   points      array of objects            
   =========== ================ ===========

dhcp (object)
^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======================= ================ ===========
   Name                    Type             Description
   ======================= ================ ===========
   assigned_ip             string                      
   client_id               string                      
   client_ip               string                      
   client_mac              string                      
   dhcp_type               string                      
   hostname                string                      
   id                      integer                     
   lease_time              integer                     
   next_server_ip          string                      
   rebinding_time          integer                     
   relay_ip                string                      
   renewal_time            integer                     
   requested_ip            string                      
   subnet_mask             string                      
   type                    string                      
   vendor_class_identifier string                      
   dns_servers             array of strings            
   params                  array of strings            
   routers                 array of strings            
   ======================= ================ ===========

dcerpc (object)
^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============ ================ ===========
   Name         Type             Description
   ============ ================ ===========
   activityuuid string                      
   call_id      integer                     
   request      string                      
   response     string                      
   rpc_version  string                      
   seqnum       integer                     
   interfaces   array of objects            
   req          object                      
   res          object                      
   ============ ================ ===========

dcerpc.res (object)
^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============== ======= ===========
   Name           Type    Description
   ============== ======= ===========
   frag_cnt       integer            
   stub_data_size integer            
   ============== ======= ===========

dcerpc.req (object)
^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============== ======= ===========
   Name           Type    Description
   ============== ======= ===========
   frag_cnt       integer            
   opnum          integer            
   stub_data_size integer            
   ============== ======= ===========

dcerpc.interfaces (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========== ======= ===========
   Name       Type    Description
   ========== ======= ===========
   ack_result integer            
   uuid       string             
   version    string             
   ========== ======= ===========

bittorrent_dht (object)
^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============== ====== ===========
   Name           Type   Description
   ============== ====== ===========
   transaction_id string            
   client_version string            
   request_type   string            
   request        object            
   response       object            
   error          object            
   ============== ====== ===========

bittorrent_dht.error (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ==== ======= ===========
   Name Type    Description
   ==== ======= ===========
   num  integer            
   msg  string             
   ==== ======= ===========

bittorrent_dht.response (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ====== ================ ===========
   Name   Type             Description
   ====== ================ ===========
   id     string                      
   nodes  array of objects            
   nodes6 array of objects            
   token  string                      
   values array of objects            
   ====== ================ ===========

bittorrent_dht.response.nodes6 (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ==== ====== ===========
   Name Type   Description
   ==== ====== ===========
   id   string            
   ip   string            
   port number            
   ==== ====== ===========

bittorrent_dht.request (object)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============ ======= ===========
   Name         Type    Description
   ============ ======= ===========
   id           string             
   target       string             
   implied_port integer            
   info_hash    string             
   port         integer            
   token        string             
   ============ ======= ===========

arp (object)
^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========== ====== ===========================================================
   Name       Type   Description                                                
   ========== ====== ===========================================================
   hw_type    string Network link protocol type                                 
   proto_type string Internetwork protocol for which the ARP request is intended
   opcode     string Specifies the operation that the sender is performing      
   src_mac    string Physical address of the sender                             
   src_ip     string Logical address of the sender                              
   dest_mac   string Physical address of the intended receiver                  
   dest_ip    string Logical address of the intended receiver                   
   ========== ====== ===========================================================

anomaly (object)
^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ========= ====== ===========
   Name      Type   Description
   ========= ====== ===========
   app_proto string            
   event     string            
   layer     string            
   type      string            
   ========= ====== ===========

alert (object)
^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============ ================ ===========
   Name         Type             Description
   ============ ================ ===========
   action       string                      
   category     string                      
   gid          integer                     
   rev          integer                     
   rule         string                      
   severity     integer                     
   signature    string                      
   signature_id integer                     
   xff          string                      
   metadata     object                      
   references   array of strings            
   source       object                      
   target       object                      
   ============ ================ ===========

alert.target (object)
^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ==== ======= ===========
   Name Type    Description
   ==== ======= ===========
   ip   string             
   port integer            
   ==== ======= ===========

alert.source (object)
^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ==== ======= ===========
   Name Type    Description
   ==== ======= ===========
   ip   string             
   port integer            
   ==== ======= ===========

alert.metadata (object)
^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ================== ================ ===========
   Name               Type             Description
   ================== ================ ===========
   affected_product   array of strings            
   attack_target      array of strings            
   created_at         array of strings            
   deployment         array of strings            
   former_category    array of strings            
   malware_family     array of strings            
   policy             array of strings            
   signature_severity array of strings            
   tag                array of strings            
   updated_at         array of strings            
   ================== ================ ===========

files (array of objects)
^^^^^^^^^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ======== ================= ===========================================
   Name     Type              Description                                
   ======== ================= ===========================================
   end      integer                                                      
   filename string                                                       
   file_id  integer                                                      
   gaps     boolean                                                      
   magic    string                                                       
   md5      string                                                       
   sha1     string                                                       
   sha256   string                                                       
   size     integer                                                      
   start    integer                                                      
   state    string                                                       
   stored   boolean                                                      
   storing  boolean           the file is set to be stored when completed
   tx_id    integer                                                      
   sid      array of integers                                            
   ======== ================= ===========================================

verdict (object)
^^^^^^^^^^^^^^^^
.. table::
   :width: 100%
   :widths: 30 25 45

   ============= ================ ===========
   Name          Type             Description
   ============= ================ ===========
   action        string                      
   reject        array of strings            
   reject-target string                      
   ============= ================ ===========

