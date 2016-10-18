#ifndef UTIL_DPDK_SETUP_H
#define UTIL_DPDK_SETUP_H

/* I N C L U D E S */
#include <rte_config.h>
#include <rte_ethdev.h>

/* D E F I N E S */
//#define MBUF_SIZE           (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define MAX_PKT_BURST       (32)
#define RTE_RING_SIZE       (4096)
#define SC_RINGBUF          (rte_eth_dev_count())


#define ETHTYPE_MB          (1)
#define ETHTYPE_1G          (2)
#define ETHTYPE_10G         (4)

//#define RTE_TEST_RX_DESC_DEFAULT (128)
//#define RTE_TEST_TX_DESC_DEFAULT (512)

/*
 * brief Structure to hold port map
 */
typedef struct DpdkIntelPortMap_t
{
    uint8_t inport;
    uint8_t outport;
    uint8_t ringid;
} DpdkIntelPortMap;

typedef struct
{
    uint8_t type;
    uint8_t count;
    DpdkIntelPortMap *pmap[16];
}DpdkCoreConfig_t;

/* P R O T O T Y P E S */
int dpdkPortSetup(uint8_t portId);
int dpdkPortUnSet(uint8_t portId);
int ringBuffSetup(void);
void dpdkConfSetup(void);
int32_t dpdkEalInit(void);
uint32_t getDpdkIntelCpu(void);
uint32_t getCpuIndex(void);
uint32_t getCpuCOunt(uint32_t CpuBmp);

#endif /* util-dpdk-setup.h */
