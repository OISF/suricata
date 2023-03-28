/* Preload a PCAP file in memory. */

/* Required otherwise compiler complains of missing types such as u_char. */
#define _DEFAULT_SOURCE 1

#include <pcap.h>


/* PCAP cache list. */
typedef struct PcapCache {
    struct pcap_pkthdr pkthdr;
    const u_char *pktdata;
    struct PcapCache *next;
} PcapCache;

int preload_pcap(const char *filename, PcapCache **head, int *datalink);