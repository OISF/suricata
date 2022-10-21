/* Copyright (C) 2011-2020 Open Information Security Foundation
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
 * \ingroup afppacket
 *
 * @{
 */

/**
 * \file
 *
 * \author Eric Leblond <eric@regit.org>
 *
 * AF_PACKET socket runmode
 *
 */

#include "suricata-common.h"
#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "runmode-af-packet.h"
#include "output.h"
#include "log-httplog.h"
#include "detect-engine-mpm.h"

#include "alert-fastlog.h"
#include "alert-debuglog.h"

#include "flow-bypass.h"

#include "util-conf.h"
#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"
#include "util-device.h"
#include "util-runmodes.h"
#include "util-ioctl.h"
#include "util-ebpf.h"
#include "util-byte.h"

#include "source-af-packet.h"

extern int max_pending_packets;

const char *RunModeAFPGetDefaultMode(void)
{
    return "workers";
}

void RunModeIdsAFPRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_AFP_DEV, "single",
                              "Single threaded af-packet mode",
                              RunModeIdsAFPSingle);
    RunModeRegisterNewRunMode(RUNMODE_AFP_DEV, "workers",
                              "Workers af-packet mode, each thread does all"
                              " tasks from acquisition to logging",
                              RunModeIdsAFPWorkers);
    RunModeRegisterNewRunMode(RUNMODE_AFP_DEV, "autofp",
                              "Multi socket AF_PACKET mode.  Packets from "
                              "each flow are assigned to a single detect "
                              "thread.",
                              RunModeIdsAFPAutoFp);
    return;
}


#ifdef HAVE_AF_PACKET

static void AFPDerefConfig(void *conf)
{
    AFPIfaceConfig *pfp = (AFPIfaceConfig *)conf;
    /* Pcap config is used only once but cost of this low. */
    if (SC_ATOMIC_SUB(pfp->ref, 1) == 1) {
        SCFree(pfp);
    }
}

/* if cluster id is not set, assign it automagically, uniq value per
 * interface. */
static int cluster_id_auto = 1;

/**
 * \brief extract information from config file
 *
 * The returned structure will be freed by the thread init function.
 * This is thus necessary to or copy the structure before giving it
 * to thread or to reparse the file for each thread (and thus have
 * new structure.
 *
 * \return a AFPIfaceConfig corresponding to the interface name
 */
static void *ParseAFPConfig(const char *iface)
{
    const char *threadsstr = NULL;
    ConfNode *if_root;
    ConfNode *if_default = NULL;
    ConfNode *af_packet_node;
    const char *tmpclusterid;
    const char *tmpctype;
    const char *copymodestr;
    intmax_t value;
    int boolval;
    const char *bpf_filter = NULL;
    const char *out_iface = NULL;
    int cluster_type = PACKET_FANOUT_HASH;
    const char *ebpf_file = NULL;
    const char *active_runmode = RunmodeGetActive();

    if (iface == NULL) {
        return NULL;
    }

    AFPIfaceConfig *aconf = SCCalloc(1, sizeof(*aconf));
    if (unlikely(aconf == NULL)) {
        return NULL;
    }

    strlcpy(aconf->iface, iface, sizeof(aconf->iface));
    aconf->threads = 0;
    SC_ATOMIC_INIT(aconf->ref);
    (void) SC_ATOMIC_ADD(aconf->ref, 1);
    aconf->buffer_size = 0;
    aconf->cluster_id = 1;
    aconf->cluster_type = cluster_type | PACKET_FANOUT_FLAG_DEFRAG;
    aconf->promisc = 1;
    aconf->checksum_mode = CHECKSUM_VALIDATION_KERNEL;
    aconf->DerefFunc = AFPDerefConfig;
    aconf->flags = 0;
    aconf->bpf_filter = NULL;
    aconf->ebpf_lb_file = NULL;
    aconf->ebpf_lb_fd = -1;
    aconf->ebpf_filter_file = NULL;
    aconf->ebpf_filter_fd = -1;
    aconf->out_iface = NULL;
    aconf->copy_mode = AFP_COPY_MODE_NONE;
    aconf->block_timeout = 10;
    aconf->block_size = getpagesize() << AFP_BLOCK_SIZE_DEFAULT_ORDER;
#ifdef HAVE_PACKET_EBPF
    aconf->ebpf_t_config.cpus_count = UtilCpuGetNumProcessorsConfigured();
#endif

    if (ConfGet("bpf-filter", &bpf_filter) == 1) {
        if (strlen(bpf_filter) > 0) {
            aconf->bpf_filter = bpf_filter;
            SCLogConfig("Going to use command-line provided bpf filter '%s'",
                       aconf->bpf_filter);
        }
    }

    /* Find initial node */
    af_packet_node = ConfGetNode("af-packet");
    if (af_packet_node == NULL) {
        SCLogInfo("unable to find af-packet config using default values");
        goto finalize;
    }

    if_root = ConfFindDeviceConfig(af_packet_node, iface);
    if_default = ConfFindDeviceConfig(af_packet_node, "default");

    if (if_root == NULL && if_default == NULL) {
        SCLogInfo("unable to find af-packet config for "
                  "interface \"%s\" or \"default\", using default values",
                  iface);
        goto finalize;
    }

    /* If there is no setting for current interface use default one as main iface */
    if (if_root == NULL) {
        if_root = if_default;
        if_default = NULL;
    }

    if (active_runmode && !strcmp("single", active_runmode)) {
        aconf->threads = 1;
    } else if (ConfGetChildValueWithDefault(if_root, if_default, "threads", &threadsstr) != 1) {
        aconf->threads = 0;
    } else {
        if (threadsstr != NULL) {
            if (strcmp(threadsstr, "auto") == 0) {
                aconf->threads = 0;
            } else {
                if (StringParseInt32(&aconf->threads, 10, 0, (const char *)threadsstr) < 0) {
                    SCLogWarning(SC_EINVAL, "Invalid number of "
                                            "threads, resetting to default");
                    aconf->threads = 0;
                }
            }
        }
    }

    if (ConfGetChildValueWithDefault(if_root, if_default, "copy-iface", &out_iface) == 1) {
        if (strlen(out_iface) > 0) {
            aconf->out_iface = out_iface;
        }
    }

    if (ConfGetChildValueBoolWithDefault(if_root, if_default, "use-mmap", (int *)&boolval) == 1) {
        if (!boolval) {
            SCLogWarning(SC_WARN_OPTION_OBSOLETE,
                    "%s: \"use-mmap\" option is obsolete: mmap is always enabled", aconf->iface);
        }
    }

    (void)ConfGetChildValueBoolWithDefault(if_root, if_default, "mmap-locked", (int *)&boolval);
    if (boolval) {
        SCLogConfig("Enabling locked memory for mmap on iface %s", aconf->iface);
        aconf->flags |= AFP_MMAP_LOCKED;
    }

    if (ConfGetChildValueBoolWithDefault(if_root, if_default, "tpacket-v3", (int *)&boolval) == 1) {
        if (boolval) {
            if (strcasecmp(RunmodeGetActive(), "workers") == 0) {
#ifdef HAVE_TPACKET_V3
                SCLogConfig("Enabling tpacket v3 capture on iface %s", aconf->iface);
                aconf->flags |= AFP_TPACKET_V3;
#else
                SCLogNotice("System too old for tpacket v3 switching to v2");
                aconf->flags &= ~AFP_TPACKET_V3;
#endif
            } else {
                SCLogWarning(SC_ERR_RUNMODE, "tpacket v3 is only implemented for 'workers' runmode."
                                             " Switching to tpacket v2.");
                aconf->flags &= ~AFP_TPACKET_V3;
            }
        } else {
            aconf->flags &= ~AFP_TPACKET_V3;
        }
    }

    (void)ConfGetChildValueBoolWithDefault(
            if_root, if_default, "use-emergency-flush", (int *)&boolval);
    if (boolval) {
        SCLogConfig("Enabling emergency ring flush on iface %s", aconf->iface);
        aconf->flags |= AFP_EMERGENCY_MODE;
    }

    if (ConfGetChildValueWithDefault(if_root, if_default, "copy-mode", &copymodestr) == 1) {
        if (aconf->out_iface == NULL) {
            SCLogInfo("Copy mode activated but no destination"
                      " iface. Disabling feature");
        } else if (strlen(copymodestr) <= 0) {
            aconf->out_iface = NULL;
        } else if (strcmp(copymodestr, "ips") == 0) {
            SCLogInfo("AF_PACKET IPS mode activated %s->%s",
                    iface,
                    aconf->out_iface);
            aconf->copy_mode = AFP_COPY_MODE_IPS;
            if (aconf->flags & AFP_TPACKET_V3) {
                SCLogWarning(SC_ERR_RUNMODE, "Using tpacket_v3 in IPS mode will result in high latency");
            }
        } else if (strcmp(copymodestr, "tap") == 0) {
            SCLogInfo("AF_PACKET TAP mode activated %s->%s",
                    iface,
                    aconf->out_iface);
            aconf->copy_mode = AFP_COPY_MODE_TAP;
            if (aconf->flags & AFP_TPACKET_V3) {
                SCLogWarning(SC_ERR_RUNMODE, "Using tpacket_v3 in TAP mode will result in high latency");
            }
        } else {
            SCLogInfo("Invalid mode (not in tap, ips)");
        }
    }

    if (ConfGetChildValueWithDefault(if_root, if_default, "cluster-id", &tmpclusterid) != 1) {
        aconf->cluster_id = (uint16_t)(cluster_id_auto++);
    } else {
        if (StringParseUint16(&aconf->cluster_id, 10, 0, (const char *)tmpclusterid) < 0) {
            SCLogWarning(SC_EINVAL, "Invalid cluster_id, resetting to 0");
            aconf->cluster_id = 0;
        }
        SCLogDebug("Going to use cluster-id %" PRIu16, aconf->cluster_id);
    }

    if (ConfGetChildValueWithDefault(if_root, if_default, "cluster-type", &tmpctype) != 1) {
        /* default to our safest choice: flow hashing + defrag enabled */
        aconf->cluster_type = PACKET_FANOUT_HASH | PACKET_FANOUT_FLAG_DEFRAG;
        cluster_type = PACKET_FANOUT_HASH;
    } else if (strcmp(tmpctype, "cluster_round_robin") == 0) {
        SCLogConfig("Using round-robin cluster mode for AF_PACKET (iface %s)",
                aconf->iface);
        aconf->cluster_type = PACKET_FANOUT_LB;
        cluster_type = PACKET_FANOUT_LB;
    } else if (strcmp(tmpctype, "cluster_flow") == 0) {
        /* In hash mode, we also ask for defragmentation needed to
         * compute the hash */
        uint16_t defrag = 0;
        int conf_val = 0;
        SCLogConfig("Using flow cluster mode for AF_PACKET (iface %s)",
                aconf->iface);
        ConfGetChildValueBoolWithDefault(if_root, if_default, "defrag", &conf_val);
        if (conf_val) {
            SCLogConfig("Using defrag kernel functionality for AF_PACKET (iface %s)",
                    aconf->iface);
            defrag = PACKET_FANOUT_FLAG_DEFRAG;
        }
        aconf->cluster_type = PACKET_FANOUT_HASH | defrag;
        cluster_type = PACKET_FANOUT_HASH;
    } else if (strcmp(tmpctype, "cluster_cpu") == 0) {
        SCLogConfig("Using cpu cluster mode for AF_PACKET (iface %s)",
                aconf->iface);
        aconf->cluster_type = PACKET_FANOUT_CPU;
        cluster_type = PACKET_FANOUT_CPU;
    } else if (strcmp(tmpctype, "cluster_qm") == 0) {
        SCLogConfig("Using queue based cluster mode for AF_PACKET (iface %s)",
                aconf->iface);
        aconf->cluster_type = PACKET_FANOUT_QM;
        cluster_type = PACKET_FANOUT_QM;
    } else if (strcmp(tmpctype, "cluster_random") == 0) {
        SCLogConfig("Using random based cluster mode for AF_PACKET (iface %s)",
                aconf->iface);
        aconf->cluster_type = PACKET_FANOUT_RND;
        cluster_type = PACKET_FANOUT_RND;
    } else if (strcmp(tmpctype, "cluster_rollover") == 0) {
        SCLogConfig("Using rollover based cluster mode for AF_PACKET (iface %s)",
                aconf->iface);
        SCLogWarning(SC_WARN_UNCOMMON, "Rollover mode is causing severe flow "
                                       "tracking issues, use it at your own risk.");
        aconf->cluster_type = PACKET_FANOUT_ROLLOVER;
        cluster_type = PACKET_FANOUT_ROLLOVER;
#ifdef HAVE_PACKET_EBPF
    } else if (strcmp(tmpctype, "cluster_ebpf") == 0) {
        SCLogInfo("Using ebpf based cluster mode for AF_PACKET (iface %s)",
                aconf->iface);
        aconf->cluster_type = PACKET_FANOUT_EBPF;
        cluster_type = PACKET_FANOUT_EBPF;
#endif
    } else {
        SCLogWarning(SC_ERR_INVALID_CLUSTER_TYPE,"invalid cluster-type %s",tmpctype);
    }

    int conf_val = 0;
    ConfGetChildValueBoolWithDefault(if_root, if_default, "rollover", &conf_val);
    if (conf_val) {
        SCLogConfig("Using rollover kernel functionality for AF_PACKET (iface %s)",
                aconf->iface);
        aconf->cluster_type |= PACKET_FANOUT_FLAG_ROLLOVER;
        SCLogWarning(SC_WARN_UNCOMMON, "Rollover option is causing severe flow "
                                       "tracking issues, use it at your own risk.");
    }

    /*load af_packet bpf filter*/
    /* command line value has precedence */
    if (ConfGet("bpf-filter", &bpf_filter) != 1) {
        if (ConfGetChildValueWithDefault(if_root, if_default, "bpf-filter", &bpf_filter) == 1) {
            if (strlen(bpf_filter) > 0) {
                aconf->bpf_filter = bpf_filter;
                SCLogConfig("Going to use bpf filter %s", aconf->bpf_filter);
            }
        }
    }

    if (ConfGetChildValueWithDefault(if_root, if_default, "ebpf-lb-file", &ebpf_file) != 1) {
        aconf->ebpf_lb_file = NULL;
    } else {
#ifdef HAVE_PACKET_EBPF
        SCLogConfig("af-packet will use '%s' as eBPF load balancing file",
                  ebpf_file);
        aconf->ebpf_lb_file = ebpf_file;
        aconf->ebpf_t_config.flags |= EBPF_SOCKET_FILTER;
#endif
    }

#ifdef HAVE_PACKET_EBPF
    boolval = false;
    if (ConfGetChildValueBoolWithDefault(if_root, if_default, "pinned-maps", (int *)&boolval) == 1) {
        if (boolval) {
            SCLogConfig("Using pinned maps on iface %s",
                        aconf->iface);
            aconf->ebpf_t_config.flags |= EBPF_PINNED_MAPS;
        }
        const char *pinned_maps_name = NULL;
        if (ConfGetChildValueWithDefault(if_root, if_default,
                    "pinned-maps-name",
                    &pinned_maps_name) != 1) {
            aconf->ebpf_t_config.pinned_maps_name = pinned_maps_name;
        } else {
            aconf->ebpf_t_config.pinned_maps_name = NULL;
        }
    } else {
        aconf->ebpf_t_config.pinned_maps_name = NULL;
    }
#endif

#ifdef HAVE_PACKET_EBPF
    /* One shot loading of the eBPF file */
    if (aconf->ebpf_lb_file && cluster_type == PACKET_FANOUT_EBPF) {
        int ret = EBPFLoadFile(aconf->iface, aconf->ebpf_lb_file, "loadbalancer",
                               &aconf->ebpf_lb_fd,
                               &aconf->ebpf_t_config);
        if (ret != 0) {
            SCLogWarning(SC_EINVAL, "Error when loading eBPF lb file");
        }
    }
#else
    if (aconf->ebpf_lb_file) {
        SCLogError(SC_ERR_UNIMPLEMENTED, "eBPF support is not build-in");
    }
#endif

    if (ConfGetChildValueWithDefault(if_root, if_default, "ebpf-filter-file", &ebpf_file) != 1) {
        aconf->ebpf_filter_file = NULL;
    } else {
#ifdef HAVE_PACKET_EBPF
        SCLogConfig("af-packet will use '%s' as eBPF filter file",
                  ebpf_file);
        aconf->ebpf_filter_file = ebpf_file;
        aconf->ebpf_t_config.mode = AFP_MODE_EBPF_BYPASS;
        aconf->ebpf_t_config.flags |= EBPF_SOCKET_FILTER;
#endif
        ConfGetChildValueBoolWithDefault(if_root, if_default, "bypass", &conf_val);
        if (conf_val) {
#ifdef HAVE_PACKET_EBPF
            SCLogConfig("Using bypass kernel functionality for AF_PACKET (iface %s)",
                    aconf->iface);
            aconf->flags |= AFP_BYPASS;
            BypassedFlowManagerRegisterUpdateFunc(EBPFUpdateFlow, NULL);
#else
            SCLogError(SC_ERR_UNIMPLEMENTED, "Bypass set but eBPF support is not built-in");
#endif
        }
    }

    /* One shot loading of the eBPF file */
    if (aconf->ebpf_filter_file) {
#ifdef HAVE_PACKET_EBPF
        int ret = EBPFLoadFile(aconf->iface, aconf->ebpf_filter_file, "filter",
                               &aconf->ebpf_filter_fd,
                               &aconf->ebpf_t_config);
        if (ret != 0) {
            SCLogWarning(SC_EINVAL, "Error when loading eBPF filter file");
        }
#else
        SCLogError(SC_ERR_UNIMPLEMENTED, "eBPF support is not build-in");
#endif
    }

    if (ConfGetChildValueWithDefault(if_root, if_default, "xdp-filter-file", &ebpf_file) != 1) {
        aconf->xdp_filter_file = NULL;
    } else {
#ifdef HAVE_PACKET_XDP
        aconf->ebpf_t_config.mode = AFP_MODE_XDP_BYPASS;
        aconf->ebpf_t_config.flags |= EBPF_XDP_CODE;
        aconf->xdp_filter_file = ebpf_file;
        ConfGetChildValueBoolWithDefault(if_root, if_default, "bypass", &conf_val);
        if (conf_val) {
            SCLogConfig("Using bypass kernel functionality for AF_PACKET (iface %s)",
                    aconf->iface);
            aconf->flags |= AFP_XDPBYPASS;
            /* if maps are pinned we need to read them at start */
            if (aconf->ebpf_t_config.flags & EBPF_PINNED_MAPS) {
                RunModeEnablesBypassManager();
                struct ebpf_timeout_config *ebt = SCCalloc(1, sizeof(struct ebpf_timeout_config));
                if (ebt == NULL) {
                    SCLogError(SC_ENOMEM, "Flow bypass alloc error");
                } else {
                    memcpy(ebt, &(aconf->ebpf_t_config), sizeof(struct ebpf_timeout_config));
                    BypassedFlowManagerRegisterCheckFunc(NULL,
                            EBPFCheckBypassedFlowCreate,
                            (void *)ebt);
                }
            }
            BypassedFlowManagerRegisterUpdateFunc(EBPFUpdateFlow, NULL);
        }
#else
        SCLogWarning(SC_ERR_UNIMPLEMENTED, "XDP filter set but XDP support is not built-in");
#endif
#ifdef HAVE_PACKET_XDP
        const char *xdp_mode;
        if (ConfGetChildValueWithDefault(if_root, if_default, "xdp-mode", &xdp_mode) != 1) {
            aconf->xdp_mode = XDP_FLAGS_SKB_MODE;
        } else {
            if (!strcmp(xdp_mode, "soft")) {
                aconf->xdp_mode = XDP_FLAGS_SKB_MODE;
            } else if (!strcmp(xdp_mode, "driver")) {
                aconf->xdp_mode = XDP_FLAGS_DRV_MODE;
            } else if (!strcmp(xdp_mode, "hw")) {
                aconf->xdp_mode = XDP_FLAGS_HW_MODE;
                aconf->ebpf_t_config.flags |= EBPF_XDP_HW_MODE;
            } else {
                SCLogWarning(SC_EINVAL, "Invalid xdp-mode value: '%s'", xdp_mode);
            }
        }

        boolval = true;
        if (ConfGetChildValueBoolWithDefault(if_root, if_default, "use-percpu-hash", (int *)&boolval) == 1) {
            if (boolval == false) {
                SCLogConfig("Not using percpu hash on iface %s",
                        aconf->iface);
                aconf->ebpf_t_config.cpus_count = 1;
            }
        }
#endif
    }

    /* One shot loading of the eBPF file */
    if (aconf->xdp_filter_file) {
#ifdef HAVE_PACKET_XDP
        int ret = EBPFLoadFile(aconf->iface, aconf->xdp_filter_file, "xdp",
                               &aconf->xdp_filter_fd,
                               &aconf->ebpf_t_config);
        switch (ret) {
            case 1:
                SCLogInfo("Loaded pinned maps from sysfs");
                break;
            case -1:
                SCLogWarning(SC_EINVAL, "Error when loading XDP filter file");
                break;
            case 0:
                ret = EBPFSetupXDP(aconf->iface, aconf->xdp_filter_fd, aconf->xdp_mode);
                if (ret != 0) {
                    SCLogWarning(SC_EINVAL, "Error when setting up XDP");
                } else {
                    /* Try to get the xdp-cpu-redirect key */
                    const char *cpuset;
                    if (ConfGetChildValueWithDefault(if_root, if_default,
                                "xdp-cpu-redirect", &cpuset) == 1) {
                        SCLogConfig("Setting up CPU map XDP");
                        ConfNode *node = ConfGetChildWithDefault(if_root, if_default, "xdp-cpu-redirect");
                        if (node == NULL) {
                            SCLogError(SC_EINVAL, "Previously found node has disappeared");
                        } else {
                            EBPFBuildCPUSet(node, aconf->iface);
                        }
                    } else {
                        /* It will just set CPU count to 0 */
                        EBPFBuildCPUSet(NULL, aconf->iface);
                    }
                }
                /* we have a peer and we use bypass so we can set up XDP iface redirect */
                if (aconf->out_iface) {
                    EBPFSetPeerIface(aconf->iface, aconf->out_iface);
                }
        }
#else
        SCLogError(SC_ERR_UNIMPLEMENTED, "XDP support is not built-in");
#endif
    }

    if ((ConfGetChildValueIntWithDefault(if_root, if_default, "buffer-size", &value)) == 1) {
        aconf->buffer_size = value;
    } else {
        aconf->buffer_size = 0;
    }
    if ((ConfGetChildValueIntWithDefault(if_root, if_default, "ring-size", &value)) == 1) {
        aconf->ring_size = value;
    }

    if ((ConfGetChildValueIntWithDefault(if_root, if_default, "block-size", &value)) == 1) {
        if (value % getpagesize()) {
            SCLogError(SC_EINVAL, "Block-size must be a multiple of pagesize.");
        } else {
            aconf->block_size = value;
        }
    }

    if ((ConfGetChildValueIntWithDefault(if_root, if_default, "block-timeout", &value)) == 1) {
        aconf->block_timeout = value;
    } else {
        aconf->block_timeout = 10;
    }

    (void)ConfGetChildValueBoolWithDefault(if_root, if_default, "disable-promisc", (int *)&boolval);
    if (boolval) {
        SCLogConfig("Disabling promiscuous mode on iface %s",
                aconf->iface);
        aconf->promisc = 0;
    }

    if (ConfGetChildValueWithDefault(if_root, if_default, "checksum-checks", &tmpctype) == 1) {
        if (strcmp(tmpctype, "auto") == 0) {
            aconf->checksum_mode = CHECKSUM_VALIDATION_AUTO;
        } else if (ConfValIsTrue(tmpctype)) {
            aconf->checksum_mode = CHECKSUM_VALIDATION_ENABLE;
        } else if (ConfValIsFalse(tmpctype)) {
            aconf->checksum_mode = CHECKSUM_VALIDATION_DISABLE;
        } else if (strcmp(tmpctype, "kernel") == 0) {
            aconf->checksum_mode = CHECKSUM_VALIDATION_KERNEL;
        } else {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid value for checksum-checks for %s", aconf->iface);
        }
    }

finalize:

    /* if the number of threads is not 1, we need to first check if fanout
     * functions on this system. */
    if (aconf->threads != 1) {
        if (AFPIsFanoutSupported(aconf->cluster_id) == 0) {
            if (aconf->threads != 0) {
                SCLogNotice("fanout not supported on this system, falling "
                        "back to 1 capture thread");
            }
            aconf->threads = 1;
        }
    }

    /* try to automagically set the proper number of threads */
    if (aconf->threads == 0) {
        /* for cluster_flow use core count */
        if (cluster_type == PACKET_FANOUT_HASH) {
            aconf->threads = (int)UtilCpuGetNumProcessorsOnline();
            SCLogPerf("%u cores, so using %u threads", aconf->threads, aconf->threads);

        /* for cluster_qm use RSS queue count */
        } else if (cluster_type == PACKET_FANOUT_QM) {
            int rss_queues = GetIfaceRSSQueuesNum(iface);
            if (rss_queues > 0) {
                aconf->threads = rss_queues;
                SCLogPerf("%d RSS queues, so using %u threads", rss_queues, aconf->threads);
            }
        }

        if (aconf->threads) {
            SCLogPerf("Using %d AF_PACKET threads for interface %s",
                    aconf->threads, iface);
        }
    }
    if (aconf->threads <= 0) {
        aconf->threads = 1;
    }
    SC_ATOMIC_RESET(aconf->ref);
    (void) SC_ATOMIC_ADD(aconf->ref, aconf->threads);

    if (aconf->ring_size != 0) {
        if (aconf->ring_size * aconf->threads < max_pending_packets) {
            aconf->ring_size = max_pending_packets / aconf->threads + 1;
            SCLogWarning(SC_ERR_AFP_CREATE, "Inefficient setup: ring-size < max_pending_packets. "
                         "Resetting to decent value %d.", aconf->ring_size);
            /* We want at least that max_pending_packets packets can be handled by the
             * interface. This is generous if we have multiple interfaces listening. */
        }
    } else {
        /* We want that max_pending_packets packets can be handled by suricata
         * for this interface. To take burst into account we multiply the obtained
         * size by 2. */
        aconf->ring_size = max_pending_packets * 2 / aconf->threads;
    }

    int ltype = AFPGetLinkType(iface);
    switch (ltype) {
        case LINKTYPE_ETHERNET:
            /* af-packet can handle csum offloading */
            if (LiveGetOffload() == 0) {
                if (GetIfaceOffloading(iface, 0, 1) == 1) {
                    SCLogWarning(SC_ERR_AFP_CREATE,
                            "Using AF_PACKET with offloading activated leads to capture problems");
                }
            } else {
                DisableIfaceOffloading(LiveGetDevice(iface), 0, 1);
            }
            break;
        case -1:
        default:
            break;
    }

    if (active_runmode == NULL || strcmp("workers", active_runmode) != 0) {
        /* If we are using copy mode we need a lock */
        aconf->flags |= AFP_SOCK_PROTECT;
        aconf->flags |= AFP_NEED_PEER;
    }
    return aconf;
}

static int AFPConfigGeThreadsCount(void *conf)
{
    AFPIfaceConfig *afp = (AFPIfaceConfig *)conf;
    return afp->threads;
}

int AFPRunModeIsIPS()
{
    int nlive = LiveGetDeviceCount();
    int ldev;
    ConfNode *if_root;
    ConfNode *if_default = NULL;
    ConfNode *af_packet_node;
    int has_ips = 0;
    int has_ids = 0;

    /* Find initial node */
    af_packet_node = ConfGetNode("af-packet");
    if (af_packet_node == NULL) {
        return 0;
    }

    if_default = ConfNodeLookupKeyValue(af_packet_node, "interface", "default");

    for (ldev = 0; ldev < nlive; ldev++) {
        const char *live_dev = LiveGetDeviceName(ldev);
        if (live_dev == NULL) {
            SCLogError(SC_EINVAL, "Problem with config file");
            return 0;
        }
        const char *copymodestr = NULL;
        if_root = ConfFindDeviceConfig(af_packet_node, live_dev);

        if (if_root == NULL) {
            if (if_default == NULL) {
                SCLogError(SC_EINVAL, "Problem with config file");
                return 0;
            }
            if_root = if_default;
        }

        if (ConfGetChildValueWithDefault(if_root, if_default, "copy-mode", &copymodestr) == 1) {
            if (strcmp(copymodestr, "ips") == 0) {
                has_ips = 1;
            } else {
                has_ids = 1;
            }
        } else {
            has_ids = 1;
        }
    }

    if (has_ids && has_ips) {
        SCLogInfo("AF_PACKET mode using IPS and IDS mode");
        for (ldev = 0; ldev < nlive; ldev++) {
            const char *live_dev = LiveGetDeviceName(ldev);
            if (live_dev == NULL) {
                SCLogError(SC_EINVAL, "Problem with config file");
                return 0;
            }
            if_root = ConfNodeLookupKeyValue(af_packet_node, "interface", live_dev);
            const char *copymodestr = NULL;

            if (if_root == NULL) {
                if (if_default == NULL) {
                    SCLogError(SC_EINVAL, "Problem with config file");
                    return 0;
                }
                if_root = if_default;
            }

            if (! ((ConfGetChildValueWithDefault(if_root, if_default, "copy-mode", &copymodestr) == 1) &&
                        (strcmp(copymodestr, "ips") == 0))) {
                SCLogError(SC_ERR_INVALID_ARGUMENT,
                        "AF_PACKET IPS mode used and interface '%s' is in IDS or TAP mode. "
                        "Sniffing '%s' but expect bad result as stream-inline is activated.",
                        live_dev, live_dev);
            }
        }
    }

    return has_ips;
}

#endif


int RunModeIdsAFPAutoFp(void)
{
    SCEnter();

/* We include only if AF_PACKET is enabled */
#ifdef HAVE_AF_PACKET
    int ret;
    const char *live_dev = NULL;

    RunModeInitialize();

    TimeModeSetLive();

    (void)ConfGet("af-packet.live-interface", &live_dev);

    SCLogDebug("live_dev %s", live_dev);

    if (AFPPeersListInit() != TM_ECODE_OK) {
        FatalError(SC_ERR_FATAL, "Unable to init peers list.");
    }

    ret = RunModeSetLiveCaptureAutoFp(ParseAFPConfig,
                              AFPConfigGeThreadsCount,
                              "ReceiveAFP",
                              "DecodeAFP", thread_name_autofp,
                              live_dev);
    if (ret != 0) {
        FatalError(SC_ERR_FATAL, "Unable to start runmode");
    }

    /* In IPS mode each threads must have a peer */
    if (AFPPeersListCheck() != TM_ECODE_OK) {
        FatalError(SC_ERR_FATAL, "Some IPS capture threads did not peer.");
    }

    SCLogDebug("RunModeIdsAFPAutoFp initialised");
#endif /* HAVE_AF_PACKET */

    SCReturnInt(0);
}

/**
 * \brief Single thread version of the AF_PACKET processing.
 */
int RunModeIdsAFPSingle(void)
{
    SCEnter();
#ifdef HAVE_AF_PACKET
    int ret;
    const char *live_dev = NULL;

    RunModeInitialize();
    TimeModeSetLive();

    (void)ConfGet("af-packet.live-interface", &live_dev);

    if (AFPPeersListInit() != TM_ECODE_OK) {
        FatalError(SC_ERR_FATAL, "Unable to init peers list.");
    }

    ret = RunModeSetLiveCaptureSingle(ParseAFPConfig,
                                    AFPConfigGeThreadsCount,
                                    "ReceiveAFP",
                                    "DecodeAFP", thread_name_single,
                                    live_dev);
    if (ret != 0) {
        FatalError(SC_ERR_FATAL, "Unable to start runmode");
    }

    /* In IPS mode each threads must have a peer */
    if (AFPPeersListCheck() != TM_ECODE_OK) {
        FatalError(SC_ERR_FATAL, "Some IPS capture threads did not peer.");
    }

    SCLogDebug("RunModeIdsAFPSingle initialised");

#endif /* HAVE_AF_PACKET */
    SCReturnInt(0);
}

/**
 * \brief Workers version of the AF_PACKET processing.
 *
 * Start N threads with each thread doing all the work.
 *
 */
int RunModeIdsAFPWorkers(void)
{
    SCEnter();
#ifdef HAVE_AF_PACKET
    int ret;
    const char *live_dev = NULL;

    RunModeInitialize();
    TimeModeSetLive();

    (void)ConfGet("af-packet.live-interface", &live_dev);

    if (AFPPeersListInit() != TM_ECODE_OK) {
        FatalError(SC_ERR_FATAL, "Unable to init peers list.");
    }

    ret = RunModeSetLiveCaptureWorkers(ParseAFPConfig,
                                    AFPConfigGeThreadsCount,
                                    "ReceiveAFP",
                                    "DecodeAFP", thread_name_workers,
                                    live_dev);
    if (ret != 0) {
        FatalError(SC_ERR_FATAL, "Unable to start runmode");
    }

    /* In IPS mode each threads must have a peer */
    if (AFPPeersListCheck() != TM_ECODE_OK) {
        FatalError(SC_ERR_FATAL, "Some IPS capture threads did not peer.");
    }

    SCLogDebug("RunModeIdsAFPWorkers initialised");

#endif /* HAVE_AF_PACKET */
    SCReturnInt(0);
}

/**
 * @}
 */
