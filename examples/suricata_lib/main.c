/* Example of a client that makes use of Suricata as a library.
 *
 * This client reads the provided PCAP/stream file(s) and creates one
 * worker per file.
 */

#include "suricata-interface.h"

#include <getopt.h>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "callbacks.h"
#include "preload.h"
#include "util-base64.h"

/* Processing mode (packet|stream). */
enum InputTypes {
    TYPE_PACKET,
    TYPE_STREAM
};

/* Struct containing the context passed to the worker. */
typedef struct {
    SuricataCtx *ctx;
    const char *input_filename;
    int loop_rounds;
    int preload;
    enum InputTypes input_type;
    void *user_ctx;
} ThreadCtx;

/* Struct containing the context passed to the packet/stream handler. */
typedef struct {
    /* Pointer to the worker. */
    ThreadVars *tv;
    /* Number of sent bytes (will go in a 'stats' struct if we need more). */
    uint64_t bytes;
    /* Number of times we already iterated over the pcap. */
    uint32_t iterations;
    /* Datalink layer. */
    int datalink;
    /* PCAP cache head (when in packet mode). */
    PcapCache *pcap_cache;
    /* Stream cache head (when in stream mode). */
    StreamCache *stream_cache;
    /* User defined context. */
    void *user_ctx;
} HandlerCtx;

/* Typedef for replayer function (pcap/stream). */
typedef void (*replayer)(ThreadCtx *, HandlerCtx *);

void packetHandler(u_char *hc, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    static int i = 0;
    HandlerCtx *handler_ctx = (HandlerCtx *)hc;

    uint64_t tenant_uuid[2] = {};
    /* Use the worker address as tenant_uuid to have 1 per worker per iteration. */
    tenant_uuid[0] = (uint64_t)handler_ctx->tv + handler_ctx->iterations;

    if (suricata_handle_packet(handler_ctx->tv, packet, handler_ctx->datalink, pkthdr->ts,
                               pkthdr->len, 1, tenant_uuid, 0, handler_ctx->user_ctx)) {
        fprintf(stderr, "Error while processing packet %d from worker %p", i, handler_ctx->tv);
    }
    handler_ctx->bytes += pkthdr->len;

    i++;
}

void streamHandler(HandlerCtx *hc, FlowStreamInfo *finfo, uint32_t len, const uint8_t *data) {
    static int i = 0;

    uint64_t tenant_uuid[2] = {};
    /* Use the worker thread address as tenant_uuid to have 1 per worker. */
    tenant_uuid[0] = (uint64_t) hc->tv + hc->iterations;

    if (suricata_handle_stream(hc->tv, finfo, data, len, tenant_uuid, 0, hc->user_ctx)) {
        fprintf(stderr, "Error while processing stream segment %d from worker thread %p", i,
                hc->tv);
    }
    hc->bytes += len;

    i++;
}

/* Replay a PCAP file reading from cache if available or from disk. */
void replay_pcap(ThreadCtx *tc, HandlerCtx *hc) {
    if (tc->preload) {
        PcapCache *node = hc->pcap_cache;
        while(node) {
            packetHandler((u_char *)hc, &node->pkthdr, node->pktdata);
            node = node->next;
        }
    } else {
        /* No cache available so read the file from disk. */
        pcap_t *fp;
        char errbuf[PCAP_ERRBUF_SIZE];

        fp = pcap_open_offline(tc->input_filename, errbuf);
        if (fp == NULL) {
            fprintf(stderr, "\npcap_open_offline() failed: %s\n", errbuf);
            suricata_deinit_worker_thread(tc->ctx, hc->tv);
            pthread_exit(NULL);
        }

        hc->datalink = pcap_datalink(fp);
        if (pcap_loop(fp, 0, packetHandler, (void *)hc) < 0) {
            fprintf(stderr, "\npcap_loop() failed: %s\n", pcap_geterr(fp));
        }
        pcap_close(fp);
    }
}

/* Replay a stream file reading from cache if available or from disk. */
void replay_stream(ThreadCtx *tc, HandlerCtx *hc) {
    if (tc->preload) {
        StreamCache *node = hc->stream_cache;
        while (node) {
            streamHandler(hc, &node->finfo, node->len, node->data);
            node = node->next;
        }
    } else {
        /* No cache available so read the file from disk. */
        FILE * fp;

        fp = fopen(tc->input_filename, "r");
        if (fp == NULL) {
            fprintf(stderr, "Error while opening input file %s \n", tc->input_filename);
            suricata_deinit_worker_thread(tc->ctx, hc->tv);
            pthread_exit(NULL);
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
            uint8_t *data = malloc((length + 1) * sizeof(uint8_t));
            if (data == NULL) {
                fprintf(stderr, "Malloc for stream segment failed\n");
                fclose(fp);
                suricata_deinit_worker_thread(tc->ctx, hc->tv);
                pthread_exit(NULL);
            }

            uint32_t consumed = 0, num_decoded = 0;
            Base64Ecode res = DecodeBase64(data, b64_len, b64_data, b64_len, &consumed,
                                           &num_decoded, BASE64_MODE_STRICT);
            if (res != BASE64_ECODE_OK) {
                fprintf(stderr, "Error while decoding segment %s\n", b64_data);
                fclose(fp);
                free(data);
                suricata_deinit_worker_thread(tc->ctx, hc->tv);
                pthread_exit(NULL);
            }
            data[length] = '\0';

            streamHandler(hc, &finfo, length, data);

            /* Cleanup. */
            free(data);
        }

        fclose(fp);
    }
}

void *suricataWorker(void *td) {
    ThreadCtx *tc = (ThreadCtx *)td;
    ThreadVars *tv = suricata_initialise_worker_thread(tc->ctx, NULL);
    HandlerCtx hc = {tv, 0, 0, 0, 0, 0, tc->user_ctx};
    struct timeval start_ts, end_ts;

    suricata_worker_post_init(tv);
    if (tc->preload) {
        if (tc->input_type == TYPE_PACKET && preload_pcap(tc->input_filename, &hc.pcap_cache,
                                                          &hc.datalink) < 0) {
            fprintf(stderr, "Preloading pcap file %s failed, exiting\n", tc->input_filename);
            suricata_deinit_worker_thread(tc->ctx, tv);
            pthread_exit(NULL);
        } else if (tc->input_type == TYPE_STREAM &&
                   preload_stream(tc->input_filename, &hc.stream_cache) < 0) {
            fprintf(stderr, "Preloading stream file %s failed, exiting\n", tc->input_filename);
            suricata_deinit_worker_thread(tc->ctx, tv);
            pthread_exit(NULL);
        }
    }

    /* Get start timestamp before processing the pcap. */
    gettimeofday(&start_ts, NULL);

    /* Replay file. */
    replayer replayer_func = tc->input_type == TYPE_PACKET ? &replay_pcap : &replay_stream;
    for (int i = 0; i < tc->loop_rounds; ++i) {
        replayer_func(tc, &hc);
        hc.iterations++;
    }
    suricata_deinit_worker_thread(tc->ctx, tv);

    /* Compute stats (Mbps only for now). */
    gettimeofday(&end_ts, NULL);
    double elapsed = (end_ts.tv_sec + end_ts.tv_usec / 1000000.) - (start_ts.tv_sec +
                      start_ts.tv_usec / 1000000.);
    if (elapsed == 0) {
        elapsed++;
    }

    double bps = hc.bytes * 8 / elapsed;
    printf("File: %s\nIterations: %d\nThroughput: %fMbps\n", tc->input_filename, tc->loop_rounds,
           bps / (1024 * 1024));

    /* Cleanup. */
    if (tc->preload) {
        if (tc->input_type == TYPE_PACKET) {
            PcapCache *node = hc.pcap_cache, *prev;
            while (node) {
                prev = node;
                free((void *)prev->pktdata);
                node = node->next;
                free(prev);
            }
        } else if (tc->input_type == TYPE_STREAM) {
            StreamCache *node = hc.stream_cache, *prev;
            while (node) {
                prev = node;
                free((void *)prev->data);
                node = node->next;
                free(prev);
            }
        }
    }
}

void printUsage() {
    printf("suricata_client [options] <pcap_file(s)>\n\n"
           "%-30s %s\n%-30s %s\n%-30s %s\n%-30s %s\n%-30s %s\n%-30s %s\n%-30s %s\n\n"
           "Example usage: ./suricata_client -c suricata.yaml input.pcap\n",
           "-c", "Path to (optional) configuration file.",
           "-h", "Print this help and exit.",
           "-l", "Path to log directory.",
           "-K, --preload-pcap", "Preloads packets into RAM before sending",
           "-L, --loop=num", "Loop through the capture file(s) X times",
           "-m, --mode=mode", "Set the kind of input to feed to the engine (packet|stream)",
           "-o, --output=output", "Path of the EVE output file (eve-json.log by default)");
}

int main(int argc, char **argv) {
    int opt;
    FILE *eve_fp;
    int n_workers = 0;
    int loop_rounds = 1; /* Loop once by default. */
    int preload = 0; /* Do not preload by default. */
    enum InputTypes input_type = TYPE_PACKET; /* Process packets by default. */
    const char *config = NULL;
    const char *logdir = NULL;
    const char *output = "eve-json.log";
    const char **input_files = NULL;
    pthread_t *thread_ids;
    ThreadCtx *tc;
    SuricataCtx *ctx = NULL;

    struct option long_opts[] = {
        {"loop", required_argument, 0, 'L'},
        {"mode", required_argument, 0, 'm'},
        {"output", required_argument, 0, 'o'},
        {"preload-pcap", no_argument, 0, 'K'},
        {0, 0, 0, 0}
    };
    /* getopt_long stores the option index here. */
    int option_index = 0;
    char short_opts[] = "hKc:l:m:o:";

    /* Parse command line */
    if (argc < 2) {
        printUsage();
        return 1;
    }

    while ((opt = getopt_long(argc, argv, short_opts, long_opts, &option_index)) != -1) {
        switch (opt) {
            case 'c':
                config = optarg;
                break;
            case 'l':
                logdir = optarg;
                break;
            case 'L':
                ;
                int loop = atoi(optarg);
                if (loop) {
                    loop_rounds = loop;
                }
                break;
            case 'K':
                preload = 1;
                break;
            case 'm':
                if (strncmp(optarg, "stream", 6) == 0) {
                    input_type = TYPE_STREAM;
                } else if (strncmp(optarg, "packet", 6) != 0) {
                    /* Unknown mode. */
                    fprintf(stderr, "Unknown mode: %s. Supported modes are \"packet\" and "
                                    "\"stream\"\n", optarg);
                    return 1;
                }
                break;
            case 'o':
                output = optarg;
                break;
            case 'h':
            default:
                printUsage();
                return 1;
        }
    }

    /* Open EVE output file, if provided. */
    if (output != NULL) {
        char path[256];
        int i = 0;

        /* Full path is logidr/output. */
        if (logdir) {
            i = strlen(logdir);
            memcpy(path, logdir, i);

            /* Add '/' to full path if not provided in logdir. */
            if (logdir[i - 1] != '/') {
                path[i++] = '/';
            }
        }

        /* Append output filename to path. */
        snprintf(path + i, strlen(output) + 1, "%s", output);

        eve_fp = fopen(path, "w");
        if (eve_fp == NULL) {
            fprintf(stderr, "Failed to open EVE output file, EVE logging is disabled.\n");
        }
    }

    /* Remaining arguments are the PCAP/stream file(s). */
    if (optind == argc) {
        fprintf(stderr, "At least one input file must be provided\n");
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

    input_files = malloc(n_workers * sizeof(char *));
    if (input_files == NULL) {
        fprintf(stderr, "Failed to allocate the input files array\n");
        return 1;
    }

    for (int i = 0; i < n_workers; ++i) {
        input_files[i] = argv[optind++];
    }

    /* Reset optind for Suricata command line args. */
    optind = 1;
    ctx = suricata_create_ctx(n_workers);

    /* Register callbacks. */
    suricata_register_alert_cb(ctx, callbackAlert);
    suricata_register_fileinfo_cb(ctx, callbackFile);
    suricata_register_http_cb(ctx, callbackHttp);
    suricata_register_nta_cb(ctx, callbackNta);
    suricata_register_flow_cb(ctx, callbackFlow);
    suricata_register_flowsnip_cb(ctx, callbackFlowSnip);
    suricata_register_sig_cb(ctx, callbackSig);
    suricata_register_stats_cb(ctx, (void *)eve_fp, callbackStats);
    /* suricata_register_log_cb(ctx, callbackLog); Do not hook logs. */

    /* Load config from file, if provided. */
    suricata_config_load(ctx, config);

    /* Override runmode (required for testing as the yaml we use sets "runmode: single"). */
    suricata_config_set(ctx, "runmode", "offline");

    /* Override logdir if provided. */
    if (logdir) {
        suricata_config_set(ctx, "default-log-dir", logdir);
    }

    /* Init suricata engine. */
    suricata_init(ctx);

    /* Spawn workers. */
    for (int i = 0; i < n_workers; ++i) {
        tc[i] = (ThreadCtx){ctx, input_files[i], loop_rounds, preload, input_type, (void *)eve_fp};
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
    free(input_files);
    free(tc);

    /* Close EVE output file descriptor if opened. */
    if (eve_fp) {
        fclose(eve_fp);
    }

    return 0;
}
