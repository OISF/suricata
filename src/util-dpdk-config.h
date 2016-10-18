#/*
* config.h
*
* Customer copyright message here$
*
*  REVISION HISTORY:$
*  Date            Author          Description$
* *
* Description: 
*
*/

#ifndef  _DPDK_INI_CONFIG_H
#define  _DPDK_INI_CONFIG_H

/* I N C L U D E S */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


/* D E F I N E S */
#define SEP      "."
#define IDS      1
#define IPS      2
#define BYPASS   4
#define TRUE     1
#define FALSE    0
#define ENABLED  1
#define DISABLED 0
#define SURICATA 1
#define FIREWALL 2
#define MAXNOPORT 255

#define DROP  0x01
#define FDROP 0x02
#define ACL   0x04
#define ST    0x08

#define SURICATA_APP 0x01
#define FIREWALL_APP 0x02
#define LOAD_SUCCESS 0
#define LOAD_FAILURE 1

#define DEF_CONF_PATH    "dpdk_conf"
#define CONFIG_FILE      "sysconfig.ini"
#define BACKUP_FILE      "sysconfig.bak" //!< backup system configuration
#define RULE_FILE        "rules.ini"
#define RULE_BACKUP_FILE "rules.bak"
#define TUNE_FILE        "systune.ini"

#define STRCPY(x, y)                (strcpy((char *)x, (char *)y))
#define STRCMP(x, y)                (strcmp((char *)x, (char *)y))
#define MATCH_SECTION(inf_section) !STRCMP(section,inf_section)
#define MATCH_NAME(inf_name)       !STRCMP(name,inf_name)


/* Action Order */
#define ACTIONORDER_PASS_S    0x01
#define ACTIONORDER_DROP_S    0x02
#define ACTIONORDER_RJCT_S    0x04
#define ACTIONORDER_ALRT_S    0x08
#define ACTIONORDER_ANY_S     0xFF

#define BYPASS_MODE_S         0x01
#define INTERCEPT_MODE_S      0x01

#ifndef S_DPDK_MAX_ETHPORTS
#define S_DPDK_MAX_ETHPORTS (4)
#endif

#define S_DPDK_MAX_APPS     2
#define FLOWDIR_S2D_S       0x01
#define FLOWDIR_D2S_S       0x02
#define FLOWDIR_ANY_S       0x04

#define PORTACT_DROP        (0x01)
#define PORTACT_FDROP       (0x02)
#define PORTACT_ACL         (0x04)
#define PORTACT_ST          (0x08)
// sysconfig.ini sections and keys
#define GENERIC     "GENERIC"
#define PORTS       "Ports"
#define OPMODE      "OpMode"
#define INSPMODE    "InspMode"
#define PORT        "PORT" 
#define PORTACTION  "PortAction"
#define PMAP_S      "PMap"
#define APP1        "APP1"
#define APP         "App"
#define CORE        "Core" 
#define APP2        "APP2"
#define IPS_S       "IPS"
#define IDS_S       "IDS"
#define SURICATA_S  "SURICATA"
#define FIREWALL_S  "FIREWALL"
#define BYPASS_S    "BYPASS"
#define INTERCEPT_S "INTERCEPT"

// rule.ini sections and keys
#define CONFIG_SECTION   "CONFIG"
#define IPV4_SECTION     "IPV4"
#define IPV6_SECTION     "IPV6"
#define TOTAL_IPV4_RULES "TotalIpv4rules" 
#define TOTAL_IPV6_RULES "TotalIpv6rules" 
#define RULE_S           "Rule"
#define TUNE_GENERAL     "General"
#define CHECKSUM         "ChecksumOffload"
#define JUMBO            "Jumbo"
#define MTU              "mtu"
#define PACKETPERPORT    "PacketsPerPort"
#define MANAGEMENTCORE   "ManagementCore"

#define MAX_IPV4_RULES 1024 
#define MAX_IPV6_RULES 10

#define DPDKINTEL_GENCFG    file_config.generic_config
#define DPDKINTEL_PRTCFG    file_config.port_config
#define DPDKINTEL_TUNGNR    file_config.tune_general
#define DPDKINTEL_DEVCFG    file_config.device_config


#define RTE_TEST_RX_DESC_DEFAULT (1024)
#define RTE_TEST_TX_DESC_DEFAULT (4096)
#define NB_MBUF             (8192 * 2)
//#define NB_MBUF             (4096)
#define MBUF_SIZE           (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)

/* S T R U C T U R E S */

typedef struct 
{
    uint8_t  Port;             /* 0 - 255 */
    uint8_t  OpMode;           /* IDS | IPS */
    uint32_t PacketsPerPort;  
    uint32_t Portset;
} generic_config_t;

typedef struct
{
    uint8_t portMap;
    uint8_t ChecksumOffload;   /* enable | disable  */
    uint8_t Jumbo;             /* enable | disable  */
    uint8_t mtu;               /* enable | disable  */
} port_config_t;

typedef struct 
{
    uint8_t  ManagementCore;
} tune_general_t;

typedef struct
{
    uint8_t cpus;
} device_config_t;


typedef struct
{
    uint8_t          isDpdk:1;
    uint8_t          rsrvd:7;
    uint8_t          suricataCpuOffset;
    uint8_t          dpdkCpuCount;
    uint8_t          dpdkCpuOffset;
    uint8_t          availCpuCount;
    uint8_t          availCpus;
    tune_general_t   tune_general;
    generic_config_t generic_config;
    port_config_t    port_config[S_DPDK_MAX_ETHPORTS];
    device_config_t  device_config;
} file_config_t;

typedef struct
{
    uint8_t isDpdk:1;
    uint8_t rsrvd:7;
    uint8_t suricataCpuOffset;
    uint8_t dpdkCpuCount;
    uint8_t dpdkCpuOffset;
    uint8_t mgmtCore;
    uint8_t cpus;

    port_config_t    port_config[S_DPDK_MAX_ETHPORTS];
    generic_config_t generic_config;
}DpdkConfig_t;


typedef enum
{
   P_ANY,
   P_TCP,
   P_UDP,
   P_GRE,
   P_ICMP,
   P_SCTP,
   P_SSL,
   P_TLS,
   P_HTTP,
   P_GTP,
   P_SMTP,
   P_FTP,
   P_SMBV1,
   P_SMBV2,
   P_DNS,
   P_DCERPC,
   P_SIZE
} protocol_t;

/*prototypes*/
int32_t loadConfiguration(char *dpdk_filename);
int32_t loadTune(char * dpdkTuneFilename);
void dumpGlobalConfig(void);
void dumpMatchPattern(void);
int32_t validateGlobalConfig(void);
int32_t dpdkIntelDevSetup(void);

#endif /* _DPDK_INI_CONFIG_H_*/

