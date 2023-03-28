/* Preload a PCAP file in memory. */

#include "preload.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int preload_pcap(const char *filename, PcapCache **head, int *datalink) {
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr *pkthdr;
    const u_char *pktdata;
    PcapCache *prev;

    fp = pcap_open_offline(filename, errbuf);
    if (fp == NULL) {
        fprintf(stderr, "\npcap_open_offline() failed: %s\n", errbuf);
        return -1;
    }

    /* Set the datalink layer. */
    *datalink = pcap_datalink(fp);

    /* Read the packets and store them in the cache/ */
    int res;
    while ((res = pcap_next_ex(fp, &pkthdr, &pktdata) == 1)) {
        PcapCache *node = malloc(1 * sizeof(PcapCache));

        if (node == NULL) {
            pcap_close(fp);
            fprintf(stderr, "malloc failed\n");
            return -1;
        }

        node->pktdata = malloc(pkthdr->caplen * sizeof(u_char));
        if (node->pktdata == NULL) {
            pcap_close(fp);
            fprintf(stderr, "malloc failed\n");
            return -1;
        }

        memcpy(&node->pkthdr, pkthdr, sizeof(struct pcap_pkthdr));
        memcpy((void *)node->pktdata, pktdata, pkthdr->caplen);
        node->next = NULL;

        if (*head == NULL) {
            /* First packet of the cache. */
            *head = node;
            prev = *head;
        } else {
            prev->next = node;
            prev = node;
        }
    }

    /* Check if we exited because we reached the end of the pcap or because of an error */
    if (res < 0 && res != -2) {
        fprintf(stderr, "\npcap_next_ex() failed: %s\n", pcap_geterr(fp));
        return -1;
    }
    pcap_close(fp);

    return 0;
}