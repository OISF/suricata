#define _GNU_SOURCE

#include "util-dpdk-setup.h"
#include "util-dpdk-config.h"
#include "util-dpdk-common.h"
#include "util-error.h"
#include "util-debug.h"
#include "dpdk-include-common.h"
#include "source-dpdkintel.h"

/* D E F I N E S*/
#define SC_DPDK_MAJOR    1
#define SC_DPDK_MINOR    8
#define EAL_ARGS         12


/* E X T E R N */
extern stats_matchPattern_t stats_matchPattern;
extern uint64_t coreSet;

/* G L O B A L S */
uint8_t  portSpeed [16];
uint8_t  portSpeed10;
uint8_t  portSpeed100;
uint8_t  portSpeed1000;
uint8_t  portSpeed10000;
uint8_t  portSpeedUnknown;
uint8_t  dpdkIntelCoreCount = 0;
struct   rte_ring *srb [16];
char* argument[EAL_ARGS] = {"suricata","-c","f","-n","2", "--", "-P", "-p", "15", "--huge-dir", "/mnt/huge", NULL};
file_config_t  file_config;
struct rte_mempool * dp_pktmbuf_pool = NULL;
DpdkIntelPortMap portMap [16];
launchPtr launchFunc[5];

/* STATIC */
static const struct rte_eth_conf portConf = {
    .rxmode = {
              .split_hdr_size = 0,
              .header_split   = 0, /**< Header Split disabled */
              .hw_ip_checksum = 0, /**< IP checksum offload disabled */
              .hw_vlan_filter = 0, /**< VLAN filtering disabled */
              .jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
              .hw_strip_crc   = 0, /**< CRC stripped by hardware */
              },
    .txmode = {
              .mq_mode = ETH_MQ_TX_NONE,
              },
};

static struct rte_eth_txconf tx_conf = {
    .tx_thresh = {
        .pthresh = 32,
        .hthresh = 0,
        .wthresh = 0,
    },
    .tx_free_thresh = 32, /* Use PMD default values */
    .tx_rs_thresh = 32, /* Use PMD default values */
    .txq_flags = (ETH_TXQ_FLAGS_NOMULTSEGS |
              ETH_TXQ_FLAGS_NOVLANOFFL |
              ETH_TXQ_FLAGS_NOXSUMSCTP |
              ETH_TXQ_FLAGS_NOXSUMUDP |
              ETH_TXQ_FLAGS_NOXSUMTCP)
};

static struct rte_eth_rxconf rx_conf = {
    .rx_drop_en = 1,
};

static struct   ether_addr dp_ports_eth_addr [S_DPDK_MAX_ETHPORTS];

void initLaunchFunc(void);

int ringBuffSetup(void)
{
    char srbName [25];
    uint8_t index = 0, maxRing = 16;
    //(DPDKINTEL_GENCFG.Port > SC_RINGBUF)?SC_RINGBUF:DPDKINTEL_GENCFG.Port;

    for (index = 0; index < maxRing; index++)
    {
        sprintf(srbName, "%s%d", "RINGBUFF", index);

        srb [index] = rte_ring_create(srbName, RTE_RING_SIZE, 
                             SOCKET_ID_ANY, RING_F_SP_ENQ);

        if (NULL == srb [index])
        {
            SCLogError(SC_ERR_DPDKINTEL_MEM_FAILED, " Cannot create Ring buff %s", srbName);
            return -1;
        }
        SCLogDebug("Suricata Ring Buffer %s created", srbName);
    }

    return 0;
}

int dpdkPortUnSet(uint8_t portId)
{
    rte_eth_dev_stop(portId);

    SCLogDebug("dev stop done for Port : %u",portId);

    rte_eth_promiscuous_disable(portId);

    return 0;
}

int32_t dpdkIntelDevSetup(void)
{
    uint8_t portIndex = 0, portTotal = rte_eth_dev_count();
    uint8_t inport = 0;
    int32_t ret = 0;

    struct rte_eth_link link;
    struct rte_eth_dev_info dev_info;

    if (unlikely((DPDKINTEL_GENCFG.Port <= 0) || (DPDKINTEL_GENCFG.Port > portTotal))){
        SCLogError(SC_ERR_DPDKINTEL_CONFIG_FAILED, " Ports in DPDK %d Config-file %d", 
                   portTotal, DPDKINTEL_GENCFG.Port);
        return -1;
    }
    SCLogDebug(" - DPDK ports %d config-file ports %d", portTotal, DPDKINTEL_GENCFG.Port);
    SCLogDebug(" - config-file ports bit map %x", index);

    dp_pktmbuf_pool =
             rte_mempool_create("mbuf_pool", NB_MBUF,
                        MBUF_SIZE, 32,
                        sizeof(struct rte_pktmbuf_pool_private),
                        rte_pktmbuf_pool_init, NULL,
                        rte_pktmbuf_init, NULL,
                        rte_socket_id()/*SOCKET_ID_ANY*/,
                        0/*MEMPOOL_F_SP_PUT*/);
    if (unlikely(NULL == dp_pktmbuf_pool))
    {
        SCLogError(SC_ERR_DPDKINTEL_MEM_FAILED," mbuf_pool alloc failed");
        return -1;
    }
    SCLogDebug(" - pkt MBUFF setup %p", dp_pktmbuf_pool);

    ret = ringBuffSetup();
    if (ret < 0)
    {
        SCLogError(SC_ERR_DPDKINTEL_MEM_FAILED, " DPDK Ring Buffer setup failed");
        return -11;
    }

    /* check interface PCI information
       ToDo: support for non INTEL PCI interfaces also - phase 2
     */
    for (portIndex = 0; portIndex < DPDKINTEL_GENCFG.Port; portIndex++)
    {
        memset(&dev_info, 0x00, sizeof(struct rte_eth_dev_info));
        memset(&link, 0x00, sizeof(struct rte_eth_link));

        inport = portMap [portIndex].inport;
        rte_eth_dev_info_get (inport, &dev_info);
        if (NULL == dev_info.pci_dev) {
            SCLogError(SC_ERR_DPDKINTEL_CONFIG_FAILED, "port %d PCI is NULL!",
                       inport);
            return -3;
        }

        if (dev_info.pci_dev->id.vendor_id != PCI_VENDOR_ID_INTEL) {
            SCLogError(SC_ERR_DPDKINTEL_CONFIG_FAILED,"port %d unsupported vendor",
                       inport);
            return -6;
        }

        fflush(stdout);

        /* ToDo - change default configuration to systune configuration */
        ret = rte_eth_dev_configure(inport, 1, 1, &portConf);
        if (ret < 0)
        {
            /* TODO: free mempool */
            SCLogError(SC_ERR_DPDKINTEL_CONFIG_FAILED," configure device: err=%d, port=%u\n",
                  ret, (unsigned) inport);
            return -7;
        }
        SCLogDebug(" - Configured Port %d", inport);

        rte_eth_macaddr_get(inport, 
                           &dp_ports_eth_addr[inport]);

        /* init one RX queue */
        fflush(stdout);
        ret = rte_eth_rx_queue_setup(inport, 0, RTE_TEST_RX_DESC_DEFAULT,
                                     0/*SOCKET_ID_ANY*/,
                                     NULL,
                                     dp_pktmbuf_pool);
        if (ret < 0)
        {
            /* TODO: free mempool */
            SCLogError(SC_ERR_DPDKINTEL_CONFIG_FAILED," rte_eth_rx_queue_setup: err=%d, port=%u\n",
                  ret, (unsigned) inport);
            return -8;
        }
        SCLogDebug(" - RX Queue setup Port %d", inport);

        /* init one TX queue on each port */
        fflush(stdout);
        ret = rte_eth_tx_queue_setup(inport, 0, RTE_TEST_TX_DESC_DEFAULT,
                                     0/*SOCKET_ID_ANY*/,
                                     NULL);
        if (ret < 0)
        {
            SCLogError(SC_ERR_DPDKINTEL_CONFIG_FAILED, " rte_eth_tx_queue_setup:err=%d, port=%u",
                ret, (unsigned) inport);
            return -9;
        }
        SCLogDebug(" - TX Queue setup Port %d", inport);

        /* ToDo: check this from YAML conf file - pahse 2 */
        rte_eth_promiscuous_enable(inport);

        /* check interface link, speed, duplex */
        rte_eth_link_get(inport, &link);
        if (link.link_duplex != ETH_LINK_FULL_DUPLEX) {
            SCLogError(SC_ERR_MISSING_CONFIG_PARAM,
                       " port:%u; duplex:%s, status:%s",
                       (unsigned) inport,
                       (link.link_duplex == ETH_LINK_FULL_DUPLEX)?"Full":"half",
                       (link.link_status == 1)?"up":"down");
            return -10;
        }
        portSpeed[inport] =    (link.link_speed == ETH_LINK_SPEED_10)?1:
                               (link.link_speed == ETH_LINK_SPEED_100)?2:
                               (link.link_speed == ETH_LINK_SPEED_1000)?3:
                               (link.link_speed == ETH_LINK_SPEED_10G)?4:
                               (link.link_speed == ETH_LINK_SPEED_20G)?5:
                               (link.link_speed == ETH_LINK_SPEED_40G)?6:
                               0;

        /* ToDo: add support for 20G and 40G */
        if ((link.link_speed == ETH_LINK_SPEED_20G) || 
            (link.link_speed == ETH_LINK_SPEED_40G))
        {
            SCLogError(SC_ERR_DPDKINTEL_CONFIG_FAILED, " Port %u unsupported speed %u",
                       inport, portSpeed[inport]);
            return -11;
        }
        else {
            (link.link_speed == ETH_LINK_SPEED_10)?portSpeed10++:
            (link.link_speed == ETH_LINK_SPEED_100)?portSpeed100++:
            (link.link_speed == ETH_LINK_SPEED_1000)?portSpeed1000++:
            (link.link_speed == ETH_LINK_SPEED_10G)?portSpeed10000++:
            portSpeedUnknown++;
        }

    }

    SCLogDebug("DPDK port setup over!!");
    return 0;
}


void dpdkConfSetup(void)
{
    int32_t ret = 0;
    uint8_t inport = 0, outport = 0, portIndex = 0, portBit = 0;
    
    if (!(RTE_VER_MAJOR > SC_DPDK_MAJOR)? (1):
         ((RTE_VER_MAJOR == SC_DPDK_MAJOR) &&
          (RTE_VER_MINOR >= SC_DPDK_MINOR))?(1):(0))
    {
        SCLogError(SC_ERR_MISSING_CONFIG_PARAM,"DPDK Version unsupported.Minimum Ver-1.8.0 Reqd!!!");
        exit(EXIT_FAILURE);
    }
    SCLogNotice("DPDK Version: %s", rte_version());

    ret = rte_eal_has_hugepages();
    if (unlikely(ret < 0))
    {
        SCLogError(SC_ERR_MISSING_CONFIG_PARAM, "No hugepage configured; %d ", ret);
        rte_panic("ERROR: No Huge Page\n");
        exit(EXIT_FAILURE);
    }

    ret = rte_eal_iopl_init();
    if (ret < 0)
    {
        SCLogError(SC_ERR_MISSING_CONFIG_PARAM, "DPDK IOPL init %d ", ret);
        rte_panic("ERROR: Cannot init IOPL\n");
        exit(EXIT_FAILURE);
    }

    /* display default configuration */
    dumpGlobalConfig();

    /* check gloabl configuration meets the requirements */
    if (validateGlobalConfig() != 0) {
        SCLogError(SC_ERR_MISSING_CONFIG_PARAM, "DPDK config validate!!!");
        exit(EXIT_FAILURE);
    }

    /* DPDK Interface setup*/
    if (dpdkIntelDevSetup() != 0) {
        SCLogError(SC_ERR_MISSING_CONFIG_PARAM, "DPDK dev setup!!!");
        exit(EXIT_FAILURE);
    }

    for (portIndex = 0; portIndex < DPDKINTEL_GENCFG.Port; portIndex++) {
        inport  = portMap [portIndex].inport;
        outport = portMap [portIndex].outport;

        if (((portBit >> inport) & 1)  && ((portBit >> outport) & 1 ))
            continue;

        /* check for 1G or smaller */
        if (portSpeed[inport] <= 4) {
           SCLogDebug(" Config core for %d <--> %d", inport, outport);
           dpdkIntelCoreCount++;
        }
        else {
            SCLogError(SC_ERR_DPDKINTEL_CONFIG_FAILED,
                       " Unsupported speed ");
            exit(EXIT_FAILURE);
        }

        if (portSpeed [inport] != portSpeed [outport]) {
            SCLogError(SC_ERR_DPDKINTEL_CONFIG_FAILED,
                      "Mapped ports %d <--> %d Speed Mismatch",
                      inport, outport);
            exit(EXIT_FAILURE);
        }

        portBit |= 1 << inport;
        portBit |= 1 << outport;
    }

    file_config.isDpdk = 1;
    file_config.dpdkCpuCount = rte_eth_dev_count();
    //file_config.dpdkCpuOffset = rte_lcore_count() - DPDKINTEL_GENCFG.Port;
    file_config.dpdkCpuOffset = rte_lcore_count() - dpdkIntelCoreCount;
    file_config.suricataCpuOffset = 0;

    initLaunchFunc();
}

int32_t dpdkEalInit()
{
    int ret = rte_eal_init(EAL_ARGS, (char **)argument);
    if (ret < 0)
    {
        SCLogError(SC_ERR_MISSING_CONFIG_PARAM, "DPDK EAL init %d ", ret);
        rte_panic("ERROR: Cannot init EAL\n");
        return -1;
    }
    return 0;
}

void dumpMatchPattern(void)
{
    SCLogNotice("----- Match Pattern ----");
    SCLogNotice(" * http:  %"PRId64" ",stats_matchPattern.http);
    SCLogNotice(" * ftp:   %"PRId64" ",stats_matchPattern.ftp);
    SCLogNotice(" * tls:   %"PRId64" ",stats_matchPattern.tls);
    SCLogNotice(" * dns:   %"PRId64" ",stats_matchPattern.dns);
    SCLogNotice(" * smtp:  %"PRId64" ",stats_matchPattern.smtp);
    SCLogNotice(" * ssh:   %"PRId64" ",stats_matchPattern.ssh);
    SCLogNotice(" * smb:   %"PRId64" ",stats_matchPattern.smb);
    SCLogNotice(" * smb2:  %"PRId64" ",stats_matchPattern.smb2);
    SCLogNotice(" * dcerpc:%"PRId64" ",stats_matchPattern.dcerpc);
    SCLogNotice(" * tcp:   %"PRId64" ",stats_matchPattern.tcp);
    SCLogNotice(" * udp:   %"PRId64" ",stats_matchPattern.udp);
    SCLogNotice(" * sctp:  %"PRId64" ",stats_matchPattern.sctp);
    SCLogNotice(" * icmpv6:%"PRId64" ",stats_matchPattern.icmpv6);
    SCLogNotice(" * gre:   %"PRId64" ",stats_matchPattern.gre);
    SCLogNotice(" * raw:   %"PRId64" ",stats_matchPattern.raw);
    SCLogNotice(" * ipv4:  %"PRId64" ",stats_matchPattern.ipv4);
    SCLogNotice(" * ipv6:  %"PRId64" ",stats_matchPattern.ipv6);
    SCLogNotice("-----------------------");

    return;
}

void dumpGlobalConfig(void)
{
    uint8_t index;

    SCLogNotice("----- Global DPDK-INTEL Config -----");
    SCLogNotice(" Number Of Ports  : %d", DPDKINTEL_GENCFG.Port);
    SCLogNotice(" Operation Mode   : %s", ((DPDKINTEL_GENCFG.OpMode == 1) ?"IDS":
                                           (DPDKINTEL_GENCFG.OpMode == 2) ?"IPS":"BYPASS"));
    for (index = 0; index < DPDKINTEL_GENCFG.Port; index++)
    {
        SCLogNotice(" Port:%d, Map:%d", portMap [index].inport, 
                                        portMap [index].outport);
    }
    SCLogNotice("------------------------------------");

    return;
}

uint32_t getCpuCOunt(uint32_t CpuBmp)
{
    uint32_t coreCounts = 0x00;

    do {
        if (CpuBmp)
        {
            coreCounts++;
            CpuBmp = CpuBmp & (CpuBmp - 1);
        }
    } while (CpuBmp);
    
    return coreCounts; 
}

/*  To find the core index from number*/
uint32_t getCpuIndex(void)
{
    uint32_t availCpus = getDpdkIntelCpu();
    static uint32_t cpuIndex = 0;

    if (cpuIndex)
        cpuIndex++;

    while (((availCpus >> cpuIndex) & 1) == 0)
    {
        cpuIndex++;
    }
    SCLogDebug("cpuIndex :%u", cpuIndex);

    return cpuIndex;
}

uint32_t getDpdkIntelCpu(void)
{
    uint32_t dpdkExecCores = 0x00;
    uint32_t invertCoreSet = 0x00;

    uint32_t coreBmp[32] = {0, 1, 3, 7, 15, 31, 63, 127, 255, 511, 1023, 2047, 4095,
                            8191, 16383, 32767, 65535};

    SCLogDebug("CPU Details:");
    SCLogDebug(" - core set: %u", coreSet);

    dpdkExecCores = coreBmp[rte_lcore_count()];
    SCLogDebug(" - DPDK core: %u", dpdkExecCores);

    invertCoreSet = ~(coreSet);
    SCLogDebug(" - Inverted CoreSet: %u", invertCoreSet);

    dpdkExecCores = dpdkExecCores & invertCoreSet;
    SCLogDebug("!!!! !!!! dpdkExecCores %x",dpdkExecCores);

    return dpdkExecCores;
}

void initLaunchFunc(void)
{
    launchFunc[IDS] = ReceiveDpdkPkts_IDS;
    launchFunc[IPS] = ReceiveDpdkPkts_IPS;
    launchFunc[BYPASS] = ReceiveDpdkPkts_BYPASS;

    return;
}
