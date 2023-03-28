/* Preload a PCAP file in memory. */

#include "preload.h"

#include <math.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "util-base64.h"


/* Preload a PCAP file. */
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
            free((void *)node);
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

/* Parse a stream file line. */
void parse_stream_line(char *line, FlowStreamInfo *finfo, uint32_t *length, char **b64_data) {
    /* Each line has 9 tokens. */
    char *ts = strtok_r(line, ",", &line);
    char *version = strtok_r(line, ",", &line);
    char *direction = strtok_r(line, ",", &line);
    char *src_ip = strtok_r(line, ",", &line);
    char *dst_ip = strtok_r(line, ",", &line);
    char *sp = strtok_r(line, ",", &line);
    char *dp = strtok_r(line, ",", &line);
    char *len = strtok_r(line, ",", &line);
    *b64_data = strtok_r(line, ",", &line);
    /* Remove trailing \n. */
    *(*b64_data + strlen(*b64_data) -1) = '\0';

    /* Fill flow information. */
    double timestamp = atof(ts);
    finfo->ts.tv_sec = floor(timestamp);
    finfo->ts.tv_usec = (timestamp - finfo->ts.tv_sec) * 1000000;
    char family = *version == '4' ? AF_INET : AF_INET6;
    finfo->direction = atoi(direction) == 0 ? DIRECTION_TOSERVER : DIRECTION_TOCLIENT;
    finfo->src.address_un_data32[0] = atoi(src_ip);
    finfo->src.family = family;
    finfo->dst.address_un_data32[0] = atoi(dst_ip);
    finfo->dst.family = family;
    finfo->sp = atoi(sp);
    finfo->dp = atoi(dp);
    *length = atoi(len);
}

/* Preload a stream file. */
int preload_stream(const char *filename, StreamCache **head) {
    FILE * fp;
    StreamCache *prev;

    fp = fopen(filename, "r");
    if (fp == NULL) {
        fprintf(stderr, "Error while opening input file %s \n", filename);
        return -1;
    }

    /* Set a maximum line length of 64KB. */
    char line[65535];
    while (fgets(line, sizeof(line), fp) != NULL) {
        FlowStreamInfo finfo;
        uint32_t length;
        char *b64_data;

        /* Parse the line and fill the FlowStreamInfo struct. */
        parse_stream_line(line, &finfo, &length, &b64_data);
        uint32_t b64_len = strlen(b64_data);

        /* Create node. */
        StreamCache *node = malloc(sizeof(StreamCache));
        if (node == NULL) {
            fclose(fp);
            fprintf(stderr, "malloc failed\n");
            return -1;
        }

        node->data = malloc((length + 1) * sizeof(uint8_t));
        if (node->data == NULL) {
            fclose(fp);
            free((void *)node);
            fprintf(stderr, "malloc failed\n");
            return -1;
        }

        uint32_t consumed = 0, num_decoded = 0;
        Base64Ecode res = DecodeBase64(node->data, b64_len, b64_data, b64_len, &consumed,
                                       &num_decoded, BASE64_MODE_STRICT);
        if (res != BASE64_ECODE_OK) {
            fclose(fp);
            free((void *)node->data);
            free((void *)node);
            fprintf(stderr, "Error while decoding segment %s\n", b64_data);
            return -1;
        }
        node->data[length] = '\0';

        node->finfo = finfo;
        node->len = length;
        node->next = NULL;

        if (*head == NULL) {
            /* First stream segment of the cache. */
            *head = node;
            prev = *head;
        } else {
            prev->next = node;
            prev = node;
        }
    }

    fclose(fp);
    return 0;
}