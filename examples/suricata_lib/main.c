/* Example of a client that makes use of Suricata as a library.
 *
 * This client reads the provided PCAP file(s) and spawns one
 * worker thread per file. The number of alerts generated by
 * a packet (if any) is printed to stdout.
 */

#include "suricata-interface.h"

#include <getopt.h>
#include <pcap.h>

#define DLT_NULL    0  /* BSD loopback encapsulation */
#define DLT_EN10MB  1  /* Ethernet (10Mb) */
#define DLT_EN3MB   2  /* Experimental Ethernet (3Mb) */
#define DLT_AX25    3  /* Amateur Radio AX.25 */
#define DLT_PRONET  4  /* Proteon ProNET Token Ring */
#define DLT_CHAOS   5  /* Chaos */
#define DLT_IEEE802 6  /* 802.5 Token Ring */
#define DLT_ARCNET  7  /* ARCNET, with BSD-style header */
#define DLT_SLIP    8  /* Serial Line IP */
#define DLT_PPP     9  /* Point-to-point Protocol */
#define DLT_FDDI    10 /* FDDI */

/* Struct containing the context passed to the worker thread. */
typedef struct {
    SuricataCtx *ctx;
    const char *pcap_filename;
} thread_args;

void packetHandler(u_char *tv, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    static int i = 0;

    if (suricata_handle_packet((ThreadVars *)tv, packet, DLT_EN10MB, pkthdr->ts, pkthdr->len, 1)) {
        fprintf(stderr, "Error while processing packet %d from worker thread %p", i, tv);
    }

    i++;
}

void *suricataWorker(void *td)
{
    thread_args *ta = (thread_args *)td;
    ThreadVars *tv = suricata_create_worker_thread(ta->ctx);

    // Pcap file.
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    fp = pcap_open_offline(ta->pcap_filename, errbuf);
    if (fp == NULL) {
        fprintf(stderr, "\npcap_open_offline() failed: %s\n", errbuf);
        suricata_destroy_worker_thread(ta->ctx, tv);
        pthread_exit(NULL);
    }

    if (pcap_loop(fp, 0, packetHandler, (void *)tv) < 0) {
        fprintf(stderr, "\npcap_loop() failed: %s\n", pcap_geterr(fp));
    }
    pcap_close(fp);
    suricata_destroy_worker_thread(ta->ctx, tv);
    pthread_exit(NULL);
}

void printUsage()
{
    printf("suricata_client [options] <pcap_file(s)>\n\n"
           "%-30s %s\n%-30s %s\n\n"
           "Example usage: ./suricata_client --suricata-config-str \"-c=suricata.yaml;-l=.;"
           "--runmode=offline\" input.pcap\n",
            "--suricata-config-str",
            "The Suricata command line arguments in the format \"arg1=value1;arg2-value2;\".", "-h",
            "Print this help and exit.");
}

int main(int argc, char **argv)
{
    int opt;
    int n_workers = 0;
    const char *config = NULL;
    const char **pcap_files = NULL;
    pthread_t *thread_ids = NULL;
    thread_args *ta = NULL;
    SuricataCtx *ctx = NULL;
    int retval = 0;

    struct option long_opts[] = { { "suricata-config-str", required_argument, 0, 0 },
        { 0, 0, 0, 0 } };
    /* getopt_long stores the option index here. */
    int option_index = 0;
    char short_opts[] = "h";

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
        retval = 1;
        goto on_error;
    }

    ta = malloc(n_workers * sizeof(thread_args));
    if (ta == NULL) {
        fprintf(stderr, "Failed to allocate thread_args struct\n");
        retval = 1;
        goto on_error;
    }

    pcap_files = malloc(n_workers * sizeof(char *));
    if (pcap_files == NULL) {
        fprintf(stderr, "Failed to allocate the pcap files array\n");
        retval = 1;
        goto on_error;
    }

    for (int i = 0; i < n_workers; ++i) {
        pcap_files[i] = argv[optind++];
    }

    /* Reset optind for Suricata command line args. */
    optind = 1;
    ctx = suricata_create_ctx(n_workers);

    /* Register callbacks. */
#if 0
    suricata_register_alert_cb(ctx, NULL, callbackAlert);
    suricata_register_fileinfo_cb(ctx, NULL, callbackFile);
    suricata_register_http_cb(ctx, NULL, callbackHttp);
    suricata_register_flow_cb(ctx, NULL, callbackFlow);
#endif

    /* Init suricata engine. */
    suricata_init(config);

    /* Spawn worker threads. */
    for (int i = 0; i < n_workers; ++i) {
        ta[i] = (thread_args){ ctx, pcap_files[i] };
        pthread_create(&thread_ids[i], NULL, suricataWorker, &ta[i]);
    }

    /* Finish initialization. */
    suricata_post_init(ctx);

    /* Shutdown the engine (main thread will wait for the worker threads to do their job). */
    suricata_shutdown(ctx);
    ctx = NULL;

    for (int i = 0; i < n_workers; ++i) {
        pthread_join(thread_ids[i], NULL);
    }

on_error:
    if (thread_ids != NULL) {
        free(thread_ids);
    }
    if (pcap_files != NULL) {
        free(pcap_files);
    }
    if (ta != NULL) {
        free(ta);
    }

    return retval;
}
