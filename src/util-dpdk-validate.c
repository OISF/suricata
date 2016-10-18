/*I N C L U D E S */
#define _GNU_SOURCE 

#include "dpdk-include-common.h"

/* E X T E R N S */
extern file_config_t file_config;
extern DpdkIntelPortMap portMap [16];

#if 0
int32_t validateMaxPort(void)
{
    uint8_t portIndex = file_config.generic_config.Port;

    if ((portIndex <= 0) || (portIndex > S_DPDK_MAX_ETHPORTS))
    {
        MSG("INFO: sysconfig.ini: section: GENERIC Invalid port Number %d\n",portIndex);
        return XS_ERROR_VALIDATION;
    }
    return XS_SUCCESS;
}
#endif

int32_t validateMap(void)
{
    uint8_t portTotal = DPDKINTEL_GENCFG.Port;
    uint8_t index, outIndex;
//    uint16_t mapArray = 0;


    for (index = 0; index < portTotal; index++)
    {
        for (outIndex = 0; outIndex < portTotal; outIndex++)
        {
            if ((portMap [index].inport == portMap [outIndex].outport) &&
                (portMap [outIndex].inport == portMap[index].outport))
            {
                SCLogDebug("Validate PortMap: Inport: %u OutPort: %u InIndex: %u OutIndex: %u"
                             , portMap [index].inport, portMap [outIndex].outport, index, outIndex);
                break;
            }
            if (outIndex == (portTotal - 1))
            {
                SCLogError(SC_ERR_DPDKINTEL_CONFIG_FAILED, "No Mapping found for Port: %u", portMap [index].inport);
                return -1;
            }
        }

    }

    return XS_SUCCESS;
}

int32_t validateGlobalConfig(void)
{
    SCLogDebug(" ................ Validating configurations!!");
    int8_t executeThreads = 0;

    /* get total num cpu */
    DPDKINTEL_DEVCFG.cpus = rte_lcore_count();
    if ((DPDKINTEL_DEVCFG.cpus <= 1)) {
        SCLogError(SC_ERR_DPDKINTEL_CONFIG_FAILED," CPU count %d not sufficent", DPDKINTEL_DEVCFG.cpus);
        return -1;
    }
    
    SCLogDebug(" - CPU: %d", DPDKINTEL_DEVCFG.cpus);
    SCLogDebug(" - Port: %d", DPDKINTEL_GENCFG.Port);

    /* check port configuration BYPASS & IPS*/

    /* for Bypass and IPS port count should be even */
    if ((!(IDS & DPDKINTEL_GENCFG.OpMode) &&
                 (DPDKINTEL_GENCFG.Port & 0x01))) {
        SCLogError(SC_ERR_DPDKINTEL_CONFIG_FAILED, " Port exceeds %d for non IDS",
            DPDKINTEL_GENCFG.Port);
        return -2;
    }

    /* check thread and port config matches */
    if (((BYPASS & DPDKINTEL_GENCFG.OpMode) &&
                ((DPDKINTEL_DEVCFG.cpus) < DPDKINTEL_GENCFG.Port))) {
        SCLogError(SC_ERR_DPDKINTEL_CONFIG_FAILED," port %d exceeds Bypass",
            DPDKINTEL_GENCFG.Port);
        return -3;
    }

    executeThreads = (DPDKINTEL_DEVCFG.cpus/2);
    SCLogDebug(" - execute threads: %d", executeThreads);
    if ((((IPS|IDS) & DPDKINTEL_GENCFG.OpMode) &&
                ((executeThreads) < DPDKINTEL_GENCFG.Port))) {
        SCLogError(SC_ERR_DPDKINTEL_CONFIG_FAILED," port %d exceeds %s",
            DPDKINTEL_GENCFG.Port, (IPS & DPDKINTEL_GENCFG.OpMode)?"IPS":"IDS");
        return -4;
    }

    /* config interfacs - ToDo change from hard coding */

    /* check interfaces are up and running */
    return 0;
}

