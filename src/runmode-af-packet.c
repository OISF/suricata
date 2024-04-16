/* Copyright (C) 2011-2024 Open Information Security Foundation
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
#include "suricata.h"
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
#include "util-bpf.h"

extern uint16_t max_pending_packets;

const char *RunModeAFPGetDefaultMode(void)
{
    return "workers";
}

static int AFPRunModeIsIPS(void)
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
            SCLogError("Problem with config file");
            return -1;
        }
        if_root = ConfFindDeviceConfig(af_packet_node, live_dev);

        if (if_root == NULL) {
            if (if_default == NULL) {
                SCLogError("Problem with config file");
                return -1;
            }
            if_root = if_default;
        }

        const char *copymodestr = NULL;
        const char *copyifacestr = NULL;
        if (ConfGetChildValueWithDefault(if_root, if_default, "copy-mode", &copymodestr) == 1 &&
                ConfGetChildValue(if_root, "copy-iface", &copyifacestr) == 1) {
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
        SCLogError("using both IPS and TAP/IDS mode is not allowed due to undefined behavior. See "
                   "ticket #5588.");
        return -1;
    }

    return has_ips;
}

static int AFPRunModeEnableIPS(void)
{
    int r = AFPRunModeIsIPS();
    if (r == 1) {
        SCLogInfo("Setting IPS mode");
        EngineModeSetIPS();
    }
    return r;
}

void RunModeIdsAFPRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_AFP_DEV, "single", "Single threaded af-packet mode",
            RunModeIdsAFPSingle, AFPRunModeEnableIPS);
    RunModeRegisterNewRunMode(RUNMODE_AFP_DEV, "workers",
            "Workers af-packet mode, each thread does all"
            " tasks from acquisition to logging",
            RunModeIdsAFPWorkers, AFPRunModeEnableIPS);
    RunModeRegisterNewRunMode(RUNMODE_AFP_DEV, "autofp",
            "Multi socket AF_PACKET mode.  Packets from "
            "each flow are assigned to a single detect "
            "thread.",
            RunModeIdsAFPAutoFp, AFPRunModeEnableIPS);
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

    /* Find initial node */
    af_packet_node = ConfGetNode("af-packet");
    if (af_packet_node == NULL) {
        SCLogInfo("%s: unable to find af-packet config using default values", iface);
        goto finalize;
    }

    if_root = ConfFindDeviceConfig(af_packet_node, iface);
    if_default = ConfFindDeviceConfig(af_packet_node, "default");

    if (if_root == NULL && if_default == NULL) {
        SCLogInfo("%s: unable to find af-packet config for "
                  "interface \"%s\" or \"default\", using default values",
                iface, iface);
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
                    SCLogWarning("%s: invalid number of "
                                 "threads, resetting to default",
                            iface);
                    aconf->threads = 0;
                }
            }
        }
    }

    if (ConfGetChildValueWithDefault(if_root, if_default, "copy-iface", &out_iface) == 1) {
        if (out_iface != NULL) {
            if (strlen(out_iface) > 0) {
                aconf->out_iface = out_iface;
                if (strcmp(iface, out_iface) == 0) {
                    FatalError(
                            "Invalid config: interface (%s) and copy-iface (%s) can't be the same",
                            iface, out_iface);
                }
            }
        } else {
            SCLogWarning("copy-iface corresponding to %s interface cannot be NULL", iface);
        }
    }

    if (ConfGetChildValueBoolWithDefault(if_root, if_default, "use-mmap", (int *)&boolval) == 1) {
        if (!boolval) {
            SCLogWarning(
                    "%s: \"use-mmap\" option is obsolete: mmap is always enabled", aconf->iface);
        }
    }

    (void)ConfGetChildValueBoolWithDefault(if_root, if_default, "mmap-locked", (int *)&boolval);
    if (boolval) {
        SCLogConfig("%s: enabling locked memory for mmap", aconf->iface);
        aconf->flags |= AFP_MMAP_LOCKED;
    }

    if (ConfGetChildValueBoolWithDefault(if_root, if_default, "tpacket-v3", (int *)&boolval) == 1) {
        if (boolval) {
            if (strcasecmp(RunmodeGetActive(), "workers") == 0) {
#ifdef HAVE_TPACKET_V3
                SCLogConfig("%s: enabling tpacket v3", aconf->iface);
                aconf->flags |= AFP_TPACKET_V3;
#else
                SCLogWarning("%s: system too old for tpacket v3 switching to v2", iface);
                aconf->flags &= ~AFP_TPACKET_V3;
#endif
            } else {
                SCLogWarning("%s: tpacket v3 is only implemented for 'workers' runmode."
                             " Switching to tpacket v2.",
                        iface);
                aconf->flags &= ~AFP_TPACKET_V3;
            }
        } else {
            aconf->flags &= ~AFP_TPACKET_V3;
        }
    }

    (void)ConfGetChildValueBoolWithDefault(
            if_root, if_default, "use-emergency-flush", (int *)&boolval);
    if (boolval) {
        SCLogConfig("%s: using emergency ring flush", aconf->iface);
        aconf->flags |= AFP_EMERGENCY_MODE;
    }

    if (ConfGetChildValueWithDefault(if_root, if_default, "copy-mode", &copymodestr) == 1) {
        if (aconf->out_iface == NULL) {
            SCLogWarning("%s: copy mode activated but no destination"
                         " iface. Disabling feature",
                    iface);
        } else if (strlen(copymodestr) <= 0) {
            aconf->out_iface = NULL;
        } else if (strcmp(copymodestr, "ips") == 0) {
            SCLogInfo("%s: AF_PACKET IPS mode activated %s->%s", iface, iface, aconf->out_iface);
            aconf->copy_mode = AFP_COPY_MODE_IPS;
            if (aconf->flags & AFP_TPACKET_V3) {
                SCLogWarning("%s: using tpacket_v3 in IPS mode will result in high latency", iface);
            }
        } else if (strcmp(copymodestr, "tap") == 0) {
            SCLogInfo("%s: AF_PACKET TAP mode activated %s->%s", iface, iface, aconf->out_iface);
            aconf->copy_mode = AFP_COPY_MODE_TAP;
            if (aconf->flags & AFP_TPACKET_V3) {
                SCLogWarning("%s: using tpacket_v3 in TAP mode will result in high latency", iface);
            }
        } else {
            SCLogWarning("Invalid 'copy-mode' (not in tap, ips)");
        }
    }

    if (ConfGetChildValueWithDefault(if_root, if_default, "cluster-id", &tmpclusterid) != 1) {
        aconf->cluster_id = (uint16_t)(cluster_id_auto++);
    } else {
        if (StringParseUint16(&aconf->cluster_id, 10, 0, (const char *)tmpclusterid) < 0) {
            SCLogWarning("%s: invalid cluster_id, resetting to 0", iface);
            aconf->cluster_id = 0;
        }
        SCLogDebug("Going to use cluster-id %" PRIu16, aconf->cluster_id);
    }

    if (ConfGetChildValueWithDefault(if_root, if_default, "cluster-type", &tmpctype) != 1) {
        /* default to our safest choice: flow hashing + defrag enabled */
        aconf->cluster_type = PACKET_FANOUT_HASH | PACKET_FANOUT_FLAG_DEFRAG;
        cluster_type = PACKET_FANOUT_HASH;
    } else if (strcmp(tmpctype, "cluster_round_robin") == 0) {
        SCLogConfig("%s: using round-robin cluster mode for AF_PACKET", aconf->iface);
        aconf->cluster_type = PACKET_FANOUT_LB;
        cluster_type = PACKET_FANOUT_LB;
    } else if (strcmp(tmpctype, "cluster_flow") == 0 || strcmp(tmpctype, "cluster_rollover") == 0) {
        if (strcmp(tmpctype, "cluster_rollover") == 0) {
            SCLogWarning("%s: cluster_rollover deprecated; using \"cluster_flow\" instead. See "
                         "ticket #6128",
                    aconf->iface);
        }
        /* In hash mode, we also ask for defragmentation needed to
         * compute the hash */
        uint16_t defrag = 0;
        int conf_val = 0;
        SCLogConfig("%s: using flow cluster mode for AF_PACKET", aconf->iface);
        ConfGetChildValueBoolWithDefault(if_root, if_default, "defrag", &conf_val);
        if (conf_val) {
            SCLogConfig("%s: using defrag kernel functionality for AF_PACKET", aconf->iface);
            defrag = PACKET_FANOUT_FLAG_DEFRAG;
        }
        aconf->cluster_type = PACKET_FANOUT_HASH | defrag;
        cluster_type = PACKET_FANOUT_HASH;
    } else if (strcmp(tmpctype, "cluster_cpu") == 0) {
        SCLogConfig("%s: using cpu cluster mode for AF_PACKET", aconf->iface);
        aconf->cluster_type = PACKET_FANOUT_CPU;
        cluster_type = PACKET_FANOUT_CPU;
    } else if (strcmp(tmpctype, "cluster_qm") == 0) {
        SCLogConfig("%s: using queue based cluster mode for AF_PACKET", aconf->iface);
        aconf->cluster_type = PACKET_FANOUT_QM;
        cluster_type = PACKET_FANOUT_QM;
    } else if (strcmp(tmpctype, "cluster_random") == 0) {
        SCLogConfig("%s: using random based cluster mode for AF_PACKET", aconf->iface);
        aconf->cluster_type = PACKET_FANOUT_RND;
        cluster_type = PACKET_FANOUT_RND;
#ifdef HAVE_PACKET_EBPF
    } else if (strcmp(tmpctype, "cluster_ebpf") == 0) {
        SCLogInfo("%s: using ebpf based cluster mode for AF_PACKET", aconf->iface);
        aconf->cluster_type = PACKET_FANOUT_EBPF;
        cluster_type = PACKET_FANOUT_EBPF;
#endif
    } else {
        SCLogWarning("invalid cluster-type %s", tmpctype);
    }

    int conf_val = 0;
    ConfGetChildValueBoolWithDefault(if_root, if_default, "rollover", &conf_val);
    if (conf_val) {
        SCLogConfig("%s: Rollover requested for AF_PACKET but ignored -- see ticket #6128.",
                aconf->iface);
        SCLogWarning("%s: rollover option has been deprecated and will be ignored as it can cause "
                     "severe flow "
                     "tracking issues; see ticket #6128.",
                iface);
    }

    ConfSetBPFFilter(if_root, if_default, iface, &aconf->bpf_filter);

    if (ConfGetChildValueWithDefault(if_root, if_default, "ebpf-lb-file", &ebpf_file) != 1) {
        aconf->ebpf_lb_file = NULL;
    } else {
#ifdef HAVE_PACKET_EBPF
        SCLogConfig("%s: af-packet will use '%s' as eBPF load balancing file", iface, ebpf_file);
        aconf->ebpf_lb_file = ebpf_file;
        aconf->ebpf_t_config.flags |= EBPF_SOCKET_FILTER;
#endif
    }

#ifdef HAVE_PACKET_EBPF
    boolval = false;
    if (ConfGetChildValueBoolWithDefault(if_root, if_default, "pinned-maps", (int *)&boolval) == 1) {
        if (boolval) {
            SCLogConfig("%s: using pinned maps", aconf->iface);
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
            SCLogWarning("%s: failed to load eBPF lb file", iface);
        }
    }
#else
    if (aconf->ebpf_lb_file) {
        SCLogError("%s: eBPF support is not built-in", iface);
    }
#endif

    if (ConfGetChildValueWithDefault(if_root, if_default, "ebpf-filter-file", &ebpf_file) != 1) {
        aconf->ebpf_filter_file = NULL;
    } else {
#ifdef HAVE_PACKET_EBPF
        SCLogConfig("%s: af-packet will use '%s' as eBPF filter file", iface, ebpf_file);
        aconf->ebpf_filter_file = ebpf_file;
        aconf->ebpf_t_config.mode = AFP_MODE_EBPF_BYPASS;
        aconf->ebpf_t_config.flags |= EBPF_SOCKET_FILTER;
#endif
        ConfGetChildValueBoolWithDefault(if_root, if_default, "bypass", &conf_val);
        if (conf_val) {
#ifdef HAVE_PACKET_EBPF
            SCLogConfig("%s: using bypass kernel functionality for AF_PACKET", aconf->iface);
            aconf->flags |= AFP_BYPASS;
            BypassedFlowManagerRegisterUpdateFunc(EBPFUpdateFlow, NULL);
#else
            SCLogError("%s: bypass set but eBPF support is not built-in", iface);
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
            SCLogWarning("%s: failed to load eBPF filter file", iface);
        }
#else
        SCLogError("%s: eBPF support is not built-in", iface);
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
            SCLogConfig("%s: using bypass kernel functionality for AF_PACKET", aconf->iface);
            aconf->flags |= AFP_XDPBYPASS;
            /* if maps are pinned we need to read them at start */
            if (aconf->ebpf_t_config.flags & EBPF_PINNED_MAPS) {
                RunModeEnablesBypassManager();
                struct ebpf_timeout_config *ebt = SCCalloc(1, sizeof(struct ebpf_timeout_config));
                if (ebt == NULL) {
                    SCLogError("%s: flow bypass alloc error", iface);
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
        SCLogWarning("%s: XDP filter set but XDP support is not built-in", iface);
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
                SCLogWarning("Invalid xdp-mode value: '%s'", xdp_mode);
            }
        }

        boolval = true;
        if (ConfGetChildValueBoolWithDefault(if_root, if_default, "use-percpu-hash", (int *)&boolval) == 1) {
            if (boolval == false) {
                SCLogConfig("%s: not using percpu hash", aconf->iface);
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
                SCLogInfo("%s: loaded pinned maps from sysfs", iface);
                break;
            case -1:
                SCLogWarning("%s: failed to load XDP filter file", iface);
                break;
            case 0:
                ret = EBPFSetupXDP(aconf->iface, aconf->xdp_filter_fd, aconf->xdp_mode);
                if (ret != 0) {
                    SCLogWarning("%s: failed to set up XDP", iface);
                } else {
                    /* Try to get the xdp-cpu-redirect key */
                    const char *cpuset;
                    if (ConfGetChildValueWithDefault(if_root, if_default,
                                "xdp-cpu-redirect", &cpuset) == 1) {
                        SCLogConfig("%s: Setting up CPU map XDP", iface);
                        ConfNode *node = ConfGetChildWithDefault(if_root, if_default, "xdp-cpu-redirect");
                        if (node == NULL) {
                            SCLogError("Previously found node has disappeared");
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
        SCLogError("%s: XDP support is not built-in", iface);
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
            SCLogWarning("%s: block-size %" PRIuMAX " must be a multiple of pagesize (%u).", iface,
                    value, getpagesize());
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
        SCLogConfig("%s: disabling promiscuous mode", aconf->iface);
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
            SCLogWarning("%s: invalid value for checksum-checks", aconf->iface);
        }
    }

finalize:

    /* if the number of threads is not 1, we need to first check if fanout
     * functions on this system. */
    if (aconf->threads != 1) {
        if (AFPIsFanoutSupported(aconf->cluster_id) == 0) {
            if (aconf->threads != 0) {
                SCLogNotice("%s: fanout not supported on this system, falling "
                            "back to 1 capture thread",
                        iface);
            }
            aconf->threads = 1;
        }
    }

    /* try to automagically set the proper number of threads */
    if (aconf->threads == 0) {
        /* for cluster_flow use core count */
        if (cluster_type == PACKET_FANOUT_HASH) {
            aconf->threads = (int)UtilCpuGetNumProcessorsOnline();
            SCLogPerf("%s: cluster_flow: %u cores, using %u threads", iface, aconf->threads,
                    aconf->threads);

            /* for cluster_qm use RSS queue count */
        } else if (cluster_type == PACKET_FANOUT_QM) {
            int rss_queues = GetIfaceRSSQueuesNum(iface);
            if (rss_queues > 0) {
                aconf->threads = rss_queues;
                SCLogPerf("%s: cluster_qm: %d RSS queues, using %u threads", iface, rss_queues,
                        aconf->threads);
            }
        }

        if (aconf->threads) {
            SCLogDebug("using %d threads for interface %s", aconf->threads, iface);
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
            SCLogWarning("%s: inefficient setup: ring-size < max_pending_packets. "
                         "Resetting to decent value %d.",
                    iface, aconf->ring_size);
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
                    SCLogWarning(
                            "%s: using AF_PACKET with offloads enabled leads to capture problems",
                            iface);
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

#endif /* HAVE_AF_PACKET */

int RunModeIdsAFPAutoFp(void)
{
    SCEnter();

/* We include only if AF_PACKET is enabled */
#ifdef HAVE_AF_PACKET
    int ret;
    const char *live_dev = NULL;

    TimeModeSetLive();

    (void)ConfGet("af-packet.live-interface", &live_dev);

    SCLogDebug("live_dev %s", live_dev);

    if (AFPPeersListInit() != TM_ECODE_OK) {
        FatalError("Unable to init peers list.");
    }

    ret = RunModeSetLiveCaptureAutoFp(ParseAFPConfig, AFPConfigGeThreadsCount, "ReceiveAFP",
            "DecodeAFP", thread_name_autofp, live_dev);
    if (ret != 0) {
        FatalError("Unable to start runmode");
    }

    /* In IPS mode each threads must have a peer */
    if (AFPPeersListCheck() != TM_ECODE_OK) {
        FatalError("Some IPS capture threads did not peer.");
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

    TimeModeSetLive();

    (void)ConfGet("af-packet.live-interface", &live_dev);

    if (AFPPeersListInit() != TM_ECODE_OK) {
        FatalError("Unable to init peers list.");
    }

    ret = RunModeSetLiveCaptureSingle(ParseAFPConfig,
                                    AFPConfigGeThreadsCount,
                                    "ReceiveAFP",
                                    "DecodeAFP", thread_name_single,
                                    live_dev);
    if (ret != 0) {
        FatalError("Unable to start runmode");
    }

    /* In IPS mode each threads must have a peer */
    if (AFPPeersListCheck() != TM_ECODE_OK) {
        FatalError("Some IPS capture threads did not peer.");
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

    TimeModeSetLive();

    (void)ConfGet("af-packet.live-interface", &live_dev);

    if (AFPPeersListInit() != TM_ECODE_OK) {
        FatalError("Unable to init peers list.");
    }

    ret = RunModeSetLiveCaptureWorkers(ParseAFPConfig, AFPConfigGeThreadsCount, "ReceiveAFP",
            "DecodeAFP", thread_name_workers, live_dev);
    if (ret != 0) {
        FatalError("Unable to start runmode");
    }

    /* In IPS mode each threads must have a peer */
    if (AFPPeersListCheck() != TM_ECODE_OK) {
        FatalError("Some IPS capture threads did not peer.");
    }

    SCLogDebug("RunModeIdsAFPWorkers initialised");

#endif /* HAVE_AF_PACKET */
    SCReturnInt(0);
}

/**
 * @}
 */
