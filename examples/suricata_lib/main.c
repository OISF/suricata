/* Example of a client that makes use of Suricata as a library.
 *
 * This client reads the provided PCAP file(s) and creates one
 * worker per file.
 */

#include "suricata-interface.h"

#include <getopt.h>
#include <sys/time.h>

#include "callbacks.h"
#include "preload.h"


/* Struct containing the context passed to the worker. */
typedef struct {
    SuricataCtx *ctx;
    const char *pcap_filename;
    int loop_rounds;
    int preload;
} ThreadCtx;

/* Struct containing the context passed to the pcap handler. */
typedef struct {
    /* Pointer to the worker. */
    ThreadVars *tv;
    /* Number of sent bytes (will go in a 'stats' struct if we need more). */
    uint64_t bytes;
    /* Number of times we already iterated over the pcap. */
    uint32_t iterations;
    /* Datalink layer. */
    int datalink;
    /* PCAP cache head. */
    PcapCache *cache;
} PcapCtx;

void packetHandler(u_char *pc, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    static int i = 0;
    PcapCtx *pcap_ctx = (PcapCtx *)pc;

    uint64_t tenant_uuid[2] = {};
    /* Use the worker address as tenant_uuid to have 1 per worker per iteration. */
    tenant_uuid[0] = (uint64_t)pcap_ctx->tv + pcap_ctx->iterations;

    if (suricata_handle_packet(pcap_ctx->tv, packet, pcap_ctx->datalink, pkthdr->ts, pkthdr->len,
                               1, tenant_uuid, 0)) {
        fprintf(stderr, "Error while processing packet %d from worker %p", i, pcap_ctx->tv);
    }
    pcap_ctx->bytes += pkthdr->len;

    i++;
}

/* Replay a pcap file reading from cache if available or from disk. */
void replay_pcap(ThreadCtx *tc, PcapCtx *pc) {
    if (tc->preload) {
        PcapCache *node = pc->cache;
        while(node) {
            packetHandler((u_char *)pc, &node->pkthdr, node->pktdata);
            node = node->next;
        }
    } else {
        /* No cache available so read the file from disk. */
        pcap_t *fp;
        char errbuf[PCAP_ERRBUF_SIZE];

        fp = pcap_open_offline(tc->pcap_filename, errbuf);
        if (fp == NULL) {
            fprintf(stderr, "\npcap_open_offline() failed: %s\n", errbuf);
            suricata_deinit_worker_thread(tc->ctx, pc->tv);
            pthread_exit(NULL);
        }

        pc->datalink = pcap_datalink(fp);
        if (pcap_loop(fp, 0, packetHandler, (void *)pc) < 0) {
            fprintf(stderr, "\npcap_loop() failed: %s\n", pcap_geterr(fp));
        }
        pcap_close(fp);
    }
}

void *suricataWorker(void *td) {
    ThreadCtx *tc = (ThreadCtx *)td;
    ThreadVars *tv = suricata_initialise_worker_thread(tc->ctx);
    PcapCtx pc = {tv, 0, 0, 0 , 0};
    struct timeval start_ts, end_ts;

    if (tc->preload) {
        if (preload_pcap(tc->pcap_filename, &pc.cache, &pc.datalink) < 0) {
            fprintf(stderr, "Preloading failed, exiting\n");
            suricata_deinit_worker_thread(tc->ctx, tv);
            pthread_exit(NULL);
        }
    }

    /* Get start timestamp before proessing the pcap. */
    gettimeofday(&start_ts, NULL);

    // Pcap file.
    for (int i = 0; i < tc->loop_rounds; ++i) {
        replay_pcap(tc, &pc);
        pc.iterations++;
    }
    suricata_deinit_worker_thread(tc->ctx, tv);

    /* Compute stats (Mbps only for now). */
    gettimeofday(&end_ts, NULL);
    double elapsed = (end_ts.tv_sec + end_ts.tv_usec / 1000000.) - (start_ts.tv_sec +
                      start_ts.tv_usec / 1000000.);
    if (elapsed == 0) {
        elapsed++;
    }

    double bps = pc.bytes * 8 / elapsed;
    printf("Pcap: %s\nIterations: %d\nThroughput: %fMbps\n", tc->pcap_filename, tc->loop_rounds,
           bps / (1024 * 1024));

    /* Cleanup. */
    if (tc->preload) {
        PcapCache *node = pc.cache, *prev;
        while(node) {
            prev = node;
            free((void *)prev->pktdata);
            node = node->next;
            free(prev);
        }
    }
}

void printUsage() {
    printf("suricata_client [options] <pcap_file(s)>\n\n"
           "%-30s %s\n%-30s %s\n%-30s %s\n%-30s %s\n\n"
           "Example usage: ./suricata_client --suricata-config-str \"-c=suricata.yaml;-l=.;"
           "--runmode=offline\" input.pcap\n",
           "--suricata-config-str",
           "The Suricata command line arguments in the format \"arg1=value1;arg2-value2;\".",
           "-h", "Print this help and exit.",
           "-K, --preload-pcap", "Preloads packets into RAM before sending",
           "-l, --loop=num", "Loop through the capture file(s) X times");
}

int main(int argc, char **argv) {
    int opt;
    int n_workers = 0;
    int loop_rounds = 1;
    int preload = 0;
    const char *config = NULL;
    const char **pcap_files = NULL;
    pthread_t *thread_ids;
    ThreadCtx *tc;
    SuricataCtx *ctx = NULL;

    struct option long_opts[] = {
        {"suricata-config-str", required_argument, 0, 0},
        {"preload-pcap", no_argument, 0, 'K'},
        {"loop", required_argument, 0, 'l'},
        {0, 0, 0, 0}
    };
    /* getopt_long stores the option index here. */
    int option_index = 0;
    char short_opts[] = "hKl:";

    /* Parse command line */
    if (argc < 2) {
        printUsage();
        return 1;
    }

    while ((opt = getopt_long(argc, argv, short_opts, long_opts, &option_index)) != -1) {
        switch (opt) {
            case 0:
                if (strcmp((long_opts[option_index]).name, "suricata-config-str") == 0) {
                    config = optarg;
                }
                break;
            case 'l':
                ;
                int loop = atoi(optarg);
                if (loop) {
                    loop_rounds = loop;
                }
                break;
            case 'K':
                preload = 1;
                break;
            case 'h':
            default:
                printUsage();
                return 1;
        }
    }

    if (config == NULL) {
        fprintf(stderr, "Required option \"--suricata-config-str\" is missing\n");
        return 1;
    }

    /* Remaining arguments are the PCAP file(s). */
    if (optind == argc) {
        fprintf(stderr, "At least one PCAP file must be provided\n");
        return 1;
    }
    n_workers = argc - optind;

    thread_ids = malloc(n_workers * sizeof(pthread_t));
    if (thread_ids == NULL) {
        fprintf(stderr, "Failed to allocate the required number of thread ids\n");
        return 1;
    }

    tc = malloc(n_workers * sizeof(ThreadCtx));
    if (tc == NULL) {
        fprintf(stderr, "Failed to allocate ThreadCtx struct\n");
        return 1;
    }

    pcap_files = malloc(n_workers * sizeof(char *));
    if (pcap_files == NULL) {
        fprintf(stderr, "Failed to allocate the pcap files array\n");
        return 1;
    }

    for (int i = 0; i < n_workers; ++i) {
        pcap_files[i] = argv[optind++];
    }

    /* Reset optind for Suricata command line args. */
    optind = 1;
    ctx = suricata_create_ctx(n_workers);

    /* Register callbacks. */
    suricata_register_alert_cb(ctx, NULL, callbackAlert);
    suricata_register_fileinfo_cb(ctx, NULL, callbackFile);
    suricata_register_http_cb(ctx, NULL, callbackHttp);
    suricata_register_flow_cb(ctx, NULL, callbackFlow);
    suricata_register_sig_cb(ctx, NULL, callbackSig);

    /* Init suricata engine. */
    suricata_init(config);

    /* Spawn workers. */
    for (int i = 0; i < n_workers; ++i) {
        tc[i] = (ThreadCtx){ctx, pcap_files[i], loop_rounds, preload};
        pthread_create(&thread_ids[i], NULL, suricataWorker, &tc[i]);
    }

    /* Finish initialization. */
    suricata_post_init(ctx);

    /* Shutdown the engine (main thread will wait for the workers to do their job). */
    suricata_shutdown(ctx);
    ctx = NULL;

    for (int i = 0; i < n_workers; ++i) {
        pthread_join(thread_ids[i], NULL);
    }
    free(thread_ids);
    free(pcap_files);
    free(tc);

    return 0;
}
