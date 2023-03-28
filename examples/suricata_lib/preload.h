/* Preload a PCAP file in memory. */

/* Required otherwise compiler complains of missing types such as u_char. */
#define _DEFAULT_SOURCE 1

#include <pcap.h>

#include "suricata-interface-stream.h"


/* PCAP cache list. */
typedef struct PcapCache {
    struct pcap_pkthdr pkthdr;
    const u_char *pktdata;
    struct PcapCache *next;
} PcapCache;

/* Stream cache list. */
typedef struct StreamCache {
    FlowInfo finfo;
    uint32_t len;
    uint8_t *data;
    struct StreamCache *next;
} StreamCache;

/* Preload a PCAP file. */
int preload_pcap(const char *filename, PcapCache **head, int *datalink);

/* Parse a stream file line. */
void parse_stream_line(char *line, FlowInfo *finfo, uint32_t *length, char **b64_data);

/* Preload a stream file. */
int preload_stream(const char *filename, StreamCache **head);