/* Copyright (C) 2013 Open Information Security Foundation
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

/** \file
 *
 *  \author Eric Leblond <eric@regit.org>
 */

#include "suricata-common.h"
#include "config.h"
#include "app-layer-detect-proto.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "util-cuda.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "conf-yaml-loader.h"

#ifdef HAVE_DPDKINTEL
#include "dpdk-include-common.h"
#endif /* HAVE_DPDKINTEL */

int ListKeywords(const char *keyword_info)
{
    if (ConfYamlLoadFile(DEFAULT_CONF_FILE) != -1)
        SCLogLoadConfig(0, 0);
    MpmTableSetup();
    SpmTableSetup();
    AppLayerSetup();
    SigTableSetup(); /* load the rule keywords */
    SigTableList(keyword_info);
    exit(EXIT_SUCCESS);
}

int ListAppLayerProtocols()
{
    if (ConfYamlLoadFile(DEFAULT_CONF_FILE) != -1)
        SCLogLoadConfig(0, 0);
    MpmTableSetup();
    SpmTableSetup();
    AppLayerSetup();
    AppLayerListSupportedProtocols();

    exit(EXIT_SUCCESS);
}

#ifdef __SC_CUDA_SUPPORT__
int ListCudaCards()
{
    SCCudaInitCudaEnvironment();
    SCCudaListCards();
    exit(EXIT_SUCCESS);
}
#endif

#ifdef HAVE_DPDKINTEL
void ListDpdkIntelPorts (void)
{
    uint16_t portCount = rte_eth_dev_count(), portIndex = 0;

    uint16_t mtu;
    struct rte_eth_link link;
    struct rte_eth_dev_info info;

    printf("\n\n --- DPDK Intel Ports ---");
    printf("\n  * Overall Ports: %d ", portCount);

    if (portCount)
    {
        for (; portIndex < portCount; portIndex++)
        {
            printf("\n\n -- Port: %d", portIndex);
            if (0 == rte_eth_dev_get_mtu(portIndex, &mtu))
            {
                printf("\n  --- MTU: %d", mtu);
            }

            rte_eth_dev_info_get(portIndex, &info);
            printf("\n  --- MAX RX MTU: %u ", info.max_rx_pktlen);
            printf("\n  --- Driver: %s", info.driver_name);
            printf("\n  --- Index: %u ", info.if_index);
            printf("\n  --- Queues RX %u & TX %u", info.max_rx_queues, info.max_tx_queues);
            printf("\n  --- SRIOV VF: %u ", info.max_vfs);
            printf("\n  --- Offload RX: %u TX: %u ", info.rx_offload_capa, info.tx_offload_capa);
            printf("\n  --- CPU NUMA node: %u", (info.pci_dev->numa_node == -1)?0:info.pci_dev->numa_node);
            printf("\n  --- PCI Addr: "PCI_PRI_FMT, 
                                      info.pci_dev->addr.domain, 
                                      info.pci_dev->addr.bus, 
                                      info.pci_dev->addr.devid, 
                                      info.pci_dev->addr.function);

            rte_eth_link_get_nowait(portIndex, &link);
            /*printf("\n  --- Speed: %d", link.link_speed);
            printf("\n  --- Duplex: %s", (link.link_duplex == 1)?"Full":"Half");*/
            printf("\n  --- Status: %s", (link.link_status)?"Up":"Down");

            rte_eth_led_off(portIndex);
            printf("\n Led for 5 sec.......");
            rte_eth_led_on(portIndex);
            rte_delay_ms(5000);
            rte_eth_led_off(portIndex);
        }
    }
    printf("\n ------------------------ \n");

    return;
}
#endif /* HAVE_DPDKINTEL */
