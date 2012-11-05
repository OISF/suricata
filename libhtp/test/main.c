/*
 * LibHTP (http://www.libhtp.org)
 * Copyright 2009,2010 Ivan Ristic <ivanr@webkreator.com>
 *
 * LibHTP is an open source product, released under terms of the General Public Licence
 * version 2 (GPLv2). Please refer to the file LICENSE, which contains the complete text
 * of the license.
 *
 * In addition, there is a special exception that allows LibHTP to be freely
 * used with any OSI-approved open source licence. Please refer to the file
 * LIBHTP_LICENSING_EXCEPTION for the full text of the exception.
 *
 */

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

#include "../htp/bstr.h"
#include "../htp/htp.h"
#include "test.h"

char *home = NULL;

/**
 *
 */
int test_get(htp_cfg_t *cfg) {
    htp_connp_t *connp = NULL;

    int rc = test_run(home, "01-get.t", cfg, &connp);
    if (rc < 0) {
        if (connp != NULL) htp_connp_destroy_all(connp);
        return -1;
    }

    htp_connp_destroy_all(connp);    

    return 1;
}

/**
 *
 */
int test_post_urlencoded_chunked(htp_cfg_t *cfg) {
    htp_connp_t *connp = NULL;

    int rc = test_run(home, "04-post-urlencoded-chunked.t", cfg, &connp);
    if (rc < 0) {
        if (connp != NULL) htp_connp_destroy_all(connp);
        return -1;
    }

    htp_tx_t *tx = list_get(connp->conn->transactions, 0);

    bstr *key = NULL;
    htp_header_t *h = NULL;
    table_iterator_reset(tx->request_headers);
    while ((key = table_iterator_next(tx->request_headers, (void **) & h)) != NULL) {
        char *key = bstr_tocstr(h->name);
        char *value = bstr_tocstr(h->value);
        printf("--   HEADER [%s][%s]\n", key, value);
        free(value);
        free(key);
    }

    bstr *raw = htp_tx_get_request_headers_raw(tx);
    fprint_raw_data(stdout, "REQUEST HEADERS RAW 2", bstr_ptr(raw), bstr_len(raw));

    htp_connp_destroy_all(connp);

    return 1;
}

/**
 *
 */
int test_post_urlencoded(htp_cfg_t *cfg) {
    htp_connp_t *connp = NULL;

    int rc = test_run(home, "03-post-urlencoded.t", cfg, &connp);
    if (rc < 0) {
        if (connp != NULL) htp_connp_destroy_all(connp);
        return -1;
    }

    htp_connp_destroy_all(connp);

    return 1;
}

/**
 *
 */
int test_apache_header_parsing(htp_cfg_t *cfg) {
    htp_connp_t *connp = NULL;

    int rc = test_run(home, "02-header-test-apache2.t", cfg, &connp);
    if (rc < 0) {
        if (connp != NULL) htp_connp_destroy_all(connp);
        return -1;
    }

    htp_tx_t *tx = list_get(connp->conn->transactions, 0);
    if (tx == NULL) return -1;

    int count = 0;
    bstr *key = NULL;
    htp_header_t *h = NULL;
    table_iterator_reset(tx->request_headers);
    while ((key = table_iterator_next(tx->request_headers, (void **) & h)) != NULL) {
        char *key = bstr_tocstr(h->name);
        char *value = bstr_tocstr(h->value);
        printf("--   HEADER [%s][%s]\n", key, value);
        free(value);
        free(key);
    }

    // There must be 9 headers
    if (table_size(tx->request_headers) != 9) {
        printf("Got %i headers, but expected 9\n", table_size(tx->request_headers));
        htp_connp_destroy(connp);
        return -1;
    }

    // Check every header
    count = 0;
    key = NULL;
    h = NULL;
    table_iterator_reset(tx->request_headers);
    while ((key = table_iterator_next(tx->request_headers, (void **) & h)) != NULL) {

        switch (count) {
            case 0:
                if (bstr_cmpc(h->name, " Invalid-Folding") != 0) {
                    printf("Header %i incorrect name\n", count + 1);
                    return -1;
                }
                if (bstr_cmpc(h->value, "1") != 0) {
                    printf("Header %i incorrect value\n", count + 1);
                    return -1;
                }
                break;
            case 1:
                if (bstr_cmpc(h->name, "Valid-Folding") != 0) {
                    printf("Header %i incorrect name\n", count + 1);
                    return -1;
                }
                if (bstr_cmpc(h->value, "2 2") != 0) {
                    printf("Header %i incorrect value\n", count + 1);
                    return -1;
                }
                break;
            case 2:
                if (bstr_cmpc(h->name, "Normal-Header") != 0) {
                    printf("Header %i incorrect name\n", count + 1);
                    return -1;
                }
                if (bstr_cmpc(h->value, "3") != 0) {
                    printf("Header %i incorrect value\n", count + 1);
                    return -1;
                }
                break;
            case 3:
                if (bstr_cmpc(h->name, "Invalid Header Name") != 0) {
                    printf("Header %i incorrect name\n", count + 1);
                    return -1;
                }
                if (bstr_cmpc(h->value, "4") != 0) {
                    printf("Header %i incorrect value\n", count + 1);
                    return -1;
                }
                break;
            case 4:
                if (bstr_cmpc(h->name, "Same-Name-Headers") != 0) {
                    printf("Header %i incorrect name\n", count + 1);
                    return -1;
                }
                if (bstr_cmpc(h->value, "5, 6") != 0) {
                    printf("Header %i incorrect value\n", count + 1);
                    return -1;
                }
                break;
            case 5:
                if (bstr_cmpc(h->name, "Empty-Value-Header") != 0) {
                    printf("Header %i incorrect name\n", count + 1);
                    return -1;
                }
                if (bstr_cmpc(h->value, "") != 0) {
                    printf("Header %i incorrect value\n", count + 1);
                    return -1;
                }
                break;
            case 6:
                if (bstr_cmpc(h->name, "") != 0) {
                    printf("Header %i incorrect name\n", count + 1);
                    return -1;
                }
                if (bstr_cmpc(h->value, "8, ") != 0) {
                    printf("Header %i incorrect value\n", count + 1);
                    return -1;
                }
                break;
            case 7:
                if (bstr_cmpc(h->name, "Header-With-LWS-After") != 0) {
                    printf("Header %i incorrect name\n", count + 1);
                    return -1;
                }
                if (bstr_cmpc(h->value, "9") != 0) {
                    printf("Header %i incorrect value\n", count + 1);
                    return -1;
                }
                break;
            case 8:
            {
                bstr *b = bstr_memdup("BEFORE", 6);
                if (bstr_cmpc(h->name, "Header-With-NUL") != 0) {
                    printf("Header %i incorrect name\n", count + 1);
                    bstr_free(b);
                    return -1;
                }
                if (bstr_cmp(h->value, b) != 0) {
                    printf("Header %i incorrect value\n", count + 1);
                    bstr_free(b);
                    return -1;
                }
                bstr_free(b);
            }
                break;
        }

        count++;
    }

    htp_connp_destroy_all(connp);

    return 1;
}

/**
 *
 */
int test_expect(htp_cfg_t *cfg) {
    htp_connp_t *connp = NULL;

    int rc = test_run(home, "05-expect.t", cfg, &connp);
    if (rc < 0) {
        if (connp != NULL) htp_connp_destroy_all(connp);
        return -1;
    }

    htp_connp_destroy_all(connp);

    return 1;
}

/**
 *
 */
int test_uri_normal(htp_cfg_t *cfg) {
    htp_connp_t *connp = NULL;

    int rc = test_run(home, "06-uri-normal.t", cfg, &connp);
    if (rc < 0) {
        if (connp != NULL) htp_connp_destroy_all(connp);
        return -1;
    }

    htp_connp_destroy_all(connp);

    return 1;
}

/**
 *
 */
int test_pipelined_connection(htp_cfg_t *cfg) {
    htp_connp_t *connp = NULL;

    int rc = test_run(home, "07-pipelined-connection.t", cfg, &connp);
    if (rc < 0) {
        if (connp != NULL) htp_connp_destroy_all(connp);
        return -1;
    }

    if (list_size(connp->conn->transactions) != 2) {
        printf("Expected 2 transactions but found %i.", list_size(connp->conn->transactions));
        return -1;
    }

    if (!(connp->conn->flags & PIPELINED_CONNECTION)) {
        printf("The pipelined flag not set on a pipelined connection.");
        return -1;
    }

    htp_connp_destroy_all(connp);

    return 1;
}

/**
 *
 */
int test_not_pipelined_connection(htp_cfg_t *cfg) {
    htp_connp_t *connp = NULL;

    int rc = test_run(home, "08-not-pipelined-connection.t", cfg, &connp);
    if (rc < 0) {
        if (connp != NULL) htp_connp_destroy_all(connp);
        return -1;
    }

    if (list_size(connp->conn->transactions) != 2) {
        printf("Expected 2 transactions but found %i.", list_size(connp->conn->transactions));
        return -1;
    }

    if (connp->conn->flags & PIPELINED_CONNECTION) {
        printf("The pipelined flag set on a connection that is not pipelined.");
        return -1;
    }

    htp_tx_t *tx = list_get(connp->conn->transactions, 0);

    if (tx->flags & HTP_MULTI_PACKET_HEAD) {
        printf("The HTP_MULTI_PACKET_HEAD flag set on a single-packet transaction.");
        return -1;
    }

    htp_connp_destroy_all(connp);

    return 1;
}

/**
 *
 */
int test_multi_packet_request_head(htp_cfg_t *cfg) {
    htp_connp_t *connp = NULL;

    int rc = test_run(home, "09-multi-packet-request-head.t", cfg, &connp);
    if (rc < 0) {
        if (connp != NULL) htp_connp_destroy_all(connp);
        return -1;
    }

    if (list_size(connp->conn->transactions) != 1) {
        printf("Expected 1 transaction but found %i.", list_size(connp->conn->transactions));
        return -1;
    }

    htp_tx_t *tx = list_get(connp->conn->transactions, 0);

    if (!(tx->flags & HTP_MULTI_PACKET_HEAD)) {
        printf("The HTP_MULTI_PACKET_HEAD flag is not set on a multipacket transaction.");
        return -1;
    }

    htp_connp_destroy_all(connp);

    return 1;
}

int test_misc(htp_cfg_t *cfg) {
    htp_connp_t *connp = NULL;

    int rc = test_run(home, "misc.t", cfg, &connp);
    if (rc < 0) {
        if (connp != NULL) htp_connp_destroy_all(connp);
        return -1;
    }

    if (list_size(connp->conn->transactions) == 0) {
        printf("Expected at least one transaction");
        return -1;
    }

    htp_tx_t *tx = list_get(connp->conn->transactions, 0);

    printf("Parsed URI: %s\n", bstr_tocstr(tx->parsed_uri_incomplete->path));

    htp_connp_destroy_all(connp);

    return 1;
}

/**
 *
 */
int test_host_in_headers(htp_cfg_t *cfg) {
    htp_connp_t *connp = NULL;

    int rc = test_run(home, "10-host-in-headers.t", cfg, &connp);
    if (rc < 0) {
        if (connp != NULL) htp_connp_destroy_all(connp);
        return -1;
    }

    if (list_size(connp->conn->transactions) != 4) {
        printf("Expected 4 transactions but found %i.", list_size(connp->conn->transactions));
        return -1;
    }

    htp_tx_t *tx1 = list_get(connp->conn->transactions, 0);
    htp_tx_t *tx2 = list_get(connp->conn->transactions, 1);
    htp_tx_t *tx3 = list_get(connp->conn->transactions, 2);
    htp_tx_t *tx4 = list_get(connp->conn->transactions, 3);

    if ((tx1->parsed_uri->hostname == NULL) || (bstr_cmpc(tx1->parsed_uri->hostname, "www.example.com") != 0)) {
        printf("1) Expected 'www.example.com' as hostname, but got: %s", tx1->parsed_uri->hostname);
        return -1;
    }

    if ((tx2->parsed_uri->hostname == NULL) || (bstr_cmpc(tx2->parsed_uri->hostname, "www.example.com") != 0)) {
        printf("2) Expected 'www.example.com' as hostname, but got: %s", tx2->parsed_uri->hostname);
        return -1;
    }

    if ((tx3->parsed_uri->hostname == NULL) || (bstr_cmpc(tx3->parsed_uri->hostname, "www.example.com") != 0)) {
        printf("3) Expected 'www.example.com' as hostname, but got: %s", tx3->parsed_uri->hostname);
        return -1;
    }

    if ((tx4->parsed_uri->hostname == NULL) || (bstr_cmpc(tx4->parsed_uri->hostname, "www.example.com") != 0)) {
        printf("4) Expected 'www.example.com' as hostname, but got: %s", tx4->parsed_uri->hostname);
        return -1;
    }

    htp_connp_destroy_all(connp);

    return 1;
}

int test_response_stream_closure(htp_cfg_t *cfg) {
    htp_connp_t *connp = NULL;

    int rc = test_run(home, "11-response-stream-closure.t", cfg, &connp);
    if (rc < 0) {
        if (connp != NULL) htp_connp_destroy_all(connp);
        return -1;
    }

    if (list_size(connp->conn->transactions) == 0) {
        printf("Expected at least one transaction");
        return -1;
    }

    htp_tx_t *tx = list_get(connp->conn->transactions, 0);

    if (tx->progress != TX_PROGRESS_DONE) {
        printf("Expected the only transaction to be complete (but got %i).", tx->progress);
        return -1;
    }

    htp_connp_destroy_all(connp);

    return 1;
}

int test_connect(htp_cfg_t *cfg) {
    htp_connp_t *connp = NULL;

    int rc = test_run(home, "12-connect-request.t", cfg, &connp);
    if (rc < 0) {
        if (connp != NULL) htp_connp_destroy_all(connp);
        return -1;
    }

    if (list_size(connp->conn->transactions) == 0) {
        printf("Expected at least one transaction");
        return -1;
    }

    htp_tx_t *tx = list_get(connp->conn->transactions, 0);

    if (tx->progress != TX_PROGRESS_DONE) {
        printf("Expected the only transaction to be complete (but got %i).", tx->progress);
        return -1;
    }

    //printf("Parsed URI: %x\n", tx->parsed_uri);
    // printf("Server: %s\n", bstr_len(tx->parsed_uri->hostname), bstr_ptr(tx->parsed_uri->hostname));
    //printf("Port: %s\n", bstr_ptr(tx->parsed_uri->port));

    htp_connp_destroy_all(connp);

    return 1;
}

int test_connect_complete(htp_cfg_t *cfg) {
    htp_connp_t *connp = NULL;

    int rc = test_run(home, "15-connect-complete.t", cfg, &connp);
    if (rc < 0) {
        if (connp != NULL) htp_connp_destroy_all(connp);
        return -1;
    }

    if (list_size(connp->conn->transactions) == 0) {
        printf("Expected at least one transaction");
        return -1;
    }

    htp_tx_t *tx = list_get(connp->conn->transactions, 0);

    if (tx->progress != TX_PROGRESS_DONE) {
        printf("Expected the only transaction to be complete (but got %i).", tx->progress);
        return -1;
    }   

    htp_connp_destroy_all(connp);

    return 1;
}

int test_connect_extra(htp_cfg_t *cfg) {
    htp_connp_t *connp = NULL;

    int rc = test_run(home, "16-connect-extra.t", cfg, &connp);
    if (rc < 0) {
        if (connp != NULL) htp_connp_destroy_all(connp);
        return -1;
    }

    if (list_size(connp->conn->transactions) == 0) {
        printf("Expected at least one transaction");
        return -1;
    }

    htp_tx_t *tx = list_get(connp->conn->transactions, 0);

    if (tx->progress != TX_PROGRESS_DONE) {
        printf("Expected the only transaction to be complete (but got %i).", tx->progress);
        return -1;
    }

    htp_connp_destroy_all(connp);

    return 1;
}

int test_compressed_response_gzip_ct(htp_cfg_t *cfg) {
    htp_connp_t *connp = NULL;

    int rc = test_run(home, "13-compressed-response-gzip-ct.t", cfg, &connp);
    if (rc < 0) {
        if (connp != NULL) htp_connp_destroy_all(connp);
        return -1;
    }

    if (list_size(connp->conn->transactions) == 0) {
        printf("Expected at least one transaction");
        return -1;
    }

    htp_tx_t *tx = list_get(connp->conn->transactions, 0);

    if (tx->progress != TX_PROGRESS_DONE) {
        printf("Expected the only transaction to be complete (but got %i).", tx->progress);
        return -1;
    }

    htp_connp_destroy_all(connp);

    return 1;
}

int test_compressed_response_gzip_chunked(htp_cfg_t *cfg) {
    htp_connp_t *connp = NULL;

    int rc = test_run(home, "14-compressed-response-gzip-chunked.t", cfg, &connp);
    if (rc < 0) {
        if (connp != NULL) htp_connp_destroy_all(connp);
        return -1;
    }

    if (list_size(connp->conn->transactions) == 0) {
        printf("Expected at least one transaction");
        return -1;
    }

    htp_tx_t *tx = list_get(connp->conn->transactions, 0);

    if (tx->progress != TX_PROGRESS_DONE) {
        printf("Expected the only transaction to be complete (but got %i).", tx->progress);
        return -1;
    }

    htp_connp_destroy_all(connp);

    return 1;
}

int callback_transaction_start(htp_connp_t *connp) {
    printf("-- Callback: transaction_start\n");
    return HOOK_OK;
}

int callback_request_line(htp_connp_t *connp) {
    printf("-- Callback: request_line\n");
    return HOOK_OK;
}

int callback_request_headers(htp_connp_t *connp) {
    printf("-- Callback: request_headers\n");
    return HOOK_OK;
}

int callback_request_body_data(htp_tx_data_t *d) {
    printf("-- Callback: request_body_data\n");
    fprint_raw_data(stdout, __FUNCTION__, d->data, d->len);
    return HOOK_OK;
}

int callback_request_trailer(htp_connp_t *connp) {
    printf("-- Callback: request_trailer\n");
    return HOOK_OK;
}

int callback_request(htp_connp_t *connp) {
    printf("-- Callback: request\n");
    return HOOK_OK;
}

int callback_response_line(htp_connp_t *connp) {
    printf("-- Callback: response_line\n");
    return HOOK_OK;
}

int callback_response_headers(htp_connp_t *connp) {
    printf("-- Callback: response_headers\n");
    return HOOK_OK;
}

int callback_response_body_data(htp_tx_data_t *d) {
    printf("-- Callback: response_body_data\n");
    fprint_raw_data(stdout, __FUNCTION__, d->data, d->len);
    return HOOK_OK;
}

int callback_response_trailer(htp_connp_t *connp) {
    printf("-- Callback: response_trailer\n");
    return HOOK_OK;
}

int callback_response(htp_connp_t *connp) {
    printf("-- Callback: response\n");    
    return HOOK_OK;
}

int callback_response_destroy(htp_connp_t *connp) {
    htp_tx_destroy(connp->out_tx);
    printf("-- Destroyed transaction\n");
    return HOOK_OK;
}

int callback_log(htp_log_t *log) {    
    htp_print_log(stdout, log);
    return HOOK_OK;
}

static void print_tx(htp_connp_t *connp, htp_tx_t *tx) {
    char *request_line = bstr_tocstr(tx->request_line);
    htp_header_t *h_user_agent = table_getc(tx->request_headers, "user-agent");
    htp_header_t *h_referer = table_getc(tx->request_headers, "referer");
    char *referer, *user_agent;
    char buf[256];

    time_t t = time(NULL);
    struct tm *tmp = localtime(&t);

    strftime(buf, 255, "%d/%b/%Y:%T %z", tmp);

    if (h_user_agent == NULL) user_agent = strdup("-");
    else {
        user_agent = bstr_tocstr(h_user_agent->value);
    }

    if (h_referer == NULL) referer = strdup("-");
    else {
        referer = bstr_tocstr(h_referer->value);
    }

    printf("%s - - [%s] \"%s\" %i %i \"%s\" \"%s\"\n", connp->conn->remote_addr, buf,
        request_line, tx->response_status_number, tx->response_message_len,
        referer, user_agent);

    free(referer);
    free(user_agent);
    free(request_line);
}

static int run_directory(char *dirname, htp_cfg_t *cfg) {
    struct dirent *entry;
    char buf[1025];
    DIR *d = opendir(dirname);
    htp_connp_t *connp;

    if (d == NULL) {
        printf("Failed to open directory: %s\n", dirname);
        return -1;
    }

    while ((entry = readdir(d)) != NULL) {
        if (strncmp(entry->d_name, "stream", 6) == 0) {   
            int rc = test_run(dirname, entry->d_name, cfg, &connp);

            if (rc < 0) {
                if (connp != NULL) {
                    htp_log_t *last_error = htp_connp_get_last_error(connp);
                    if (last_error != NULL) {
                        printf(" -- failed: %s\n", last_error->msg);
                    } else {
                        printf(" -- failed: ERROR NOT AVAILABLE\n");
                    }

                    return 0;
                } else {
                    return -1;
                }
            } else {
                printf(" -- %i transaction(s)\n", list_size(connp->conn->transactions));

                htp_tx_t *tx = NULL;
                list_iterator_reset(connp->conn->transactions);
                while ((tx = list_iterator_next(connp->conn->transactions)) != NULL) {
                    printf("    ");
                    print_tx(connp, tx);
                }

                printf("\n");

                htp_connp_destroy_all(connp);
            }
        }
    }

    closedir(d);

    return 1;
}

int main_dir(int argc, char** argv) {
    htp_cfg_t *cfg = htp_config_create();
    htp_config_register_log(cfg, callback_log);
    htp_config_register_response(cfg, callback_response_destroy);
    
    run_directory("C:\\http_traces\\run5", cfg);
    //run_directory("/home/ivanr/work/traces/run3/", cfg);
    
    htp_config_destroy(cfg);
    return (EXIT_SUCCESS);
}

#define RUN_TEST(X, Y) \
    {\
    tests++; \
    printf("---------------------------------\n"); \
    printf("Test: " #X "\n"); \
    int rc = X(Y); \
    if (rc < 0) { \
        printf("    Failed with %i\n", rc); \
        failures++; \
    } \
    printf("\n"); \
    }

/**
 * Entry point; runs a bunch of tests and exits.
 */
int main(int argc, char** argv) {
    char buf[1025];
    int tests = 0, failures = 0;

    home = NULL;

    // Try the current working directory first
    int fd = open("./files/anchor.empty", 0, O_RDONLY);
    if (fd != -1) {
        close(fd);
        home = "./files";
    } else {
        // Try the directory in which the executable resides
        strncpy(buf, argv[0], 1024);
        strncat(buf, "/../files/anchor.empty", 1024 - strlen(buf));
        fd = open(buf, 0, O_RDONLY);
        if (fd != -1) {
            close(fd);
            strncpy(buf, argv[0], 1024);
            strncat(buf, "/../files", 1024 - strlen(buf));
            home = buf;
        } else {
            // Try the directory in which the executable resides
            strncpy(buf, argv[0], 1024);
            strncat(buf, "/../../files/anchor.empty", 1024 - strlen(buf));
            fd = open(buf, 0, O_RDONLY);
            if (fd != -1) {
                close(fd);
                strncpy(buf, argv[0], 1024);
                strncat(buf, "/../../files", 1024 - strlen(buf));
                home = buf;
            }
        }
    }

    if (home == NULL) {
        printf("Failed to find test files.");
        exit(-1);
    }

    htp_cfg_t *cfg = htp_config_create();
    //htp_config_set_server_personality(cfg, HTP_SERVER_GENERIC);
    htp_config_set_server_personality(cfg, HTP_SERVER_APACHE_2_2);

    // Register hooks
    htp_config_register_transaction_start(cfg, callback_transaction_start);

    htp_config_register_request_line(cfg, callback_request_line);
    htp_config_register_request_headers(cfg, callback_request_headers);
    htp_config_register_request_body_data(cfg, callback_request_body_data);
    htp_config_register_request_trailer(cfg, callback_request_trailer);
    htp_config_register_request(cfg, callback_request);

    htp_config_register_response_line(cfg, callback_response_line);
    htp_config_register_response_headers(cfg, callback_response_headers);
    htp_config_register_response_body_data(cfg, callback_response_body_data);
    htp_config_register_response_trailer(cfg, callback_response_trailer);
    htp_config_register_response(cfg, callback_response);

    htp_config_register_log(cfg, callback_log);

    htp_config_set_generate_request_uri_normalized(cfg, 1);
    
    RUN_TEST(test_get, cfg);
    //RUN_TEST(test_apache_header_parsing, cfg);
    //RUN_TEST(test_post_urlencoded, cfg);
    //RUN_TEST(test_post_urlencoded_chunked, cfg);
    //RUN_TEST(test_expect, cfg);
    //RUN_TEST(test_uri_normal, cfg);
    //RUN_TEST(test_pipelined_connection, cfg);
    //RUN_TEST(test_not_pipelined_connection, cfg);
    //RUN_TEST(test_multi_packet_request_head, cfg);
    //RUN_TEST(test_response_stream_closure, cfg);
    //RUN_TEST(test_host_in_headers, cfg);
    //RUN_TEST(test_compressed_response_gzip_ct, cfg);
    //RUN_TEST(test_compressed_response_gzip_chunked, cfg);
    
    //RUN_TEST(test_connect, cfg);
    //RUN_TEST(test_connect_complete, cfg);
    //RUN_TEST(test_connect_extra, cfg);    

    //RUN_TEST(test_misc, cfg);
    //RUN_TEST(test_post_urlencoded_chunked, cfg);

    printf("Tests: %i\n", tests);
    printf("Failures: %i\n", failures);

    htp_config_destroy(cfg);

    return (EXIT_SUCCESS);
}

int main_path_decoding_tests(int argc, char** argv) {
    htp_cfg_t *cfg = htp_config_create();
    htp_tx_t *tx = htp_tx_create(cfg, 0, NULL);

    bstr *path = NULL;

    //
    path = bstr_cstrdup("/One\\two///ThRee%2ffive%5csix/se%xxven");
    cfg->path_case_insensitive = 1;

    printf("Before: %s\n", bstr_tocstr(path));
    htp_decode_path_inplace(cfg, tx, path);
    printf("After: %s\n\n", bstr_tocstr(path));

    //
    path = bstr_cstrdup("/One\\two///ThRee%2ffive%5csix/se%xxven");
    cfg->path_case_insensitive = 1;
    cfg->path_compress_separators = 1;

    printf("Before: %s\n", bstr_tocstr(path));
    htp_decode_path_inplace(cfg, tx, path);
    printf("After: %s\n\n", bstr_tocstr(path));

    //
    path = bstr_cstrdup("/One\\two///ThRee%2ffive%5csix/se%xxven");
    cfg->path_case_insensitive = 1;
    cfg->path_compress_separators = 1;
    cfg->path_backslash_separators = 1;

    printf("Before: %s\n", bstr_tocstr(path));
    htp_decode_path_inplace(cfg, tx, path);
    printf("After: %s\n\n", bstr_tocstr(path));

    //
    path = bstr_cstrdup("/One\\two///ThRee%2ffive%5csix/se%xxven");
    cfg->path_case_insensitive = 1;
    cfg->path_compress_separators = 1;
    cfg->path_backslash_separators = 1;
    cfg->path_decode_separators = 1;

    printf("Before: %s\n", bstr_tocstr(path));
    htp_decode_path_inplace(cfg, tx, path);
    printf("After: %s\n\n", bstr_tocstr(path));

    //
    path = bstr_cstrdup("/One\\two///ThRee%2ffive%5csix/se%xxven");
    cfg->path_case_insensitive = 1;
    cfg->path_compress_separators = 1;
    cfg->path_backslash_separators = 1;
    cfg->path_decode_separators = 1;
    cfg->path_invalid_encoding_handling = URL_DECODER_REMOVE_PERCENT;

    printf("Before: %s\n", bstr_tocstr(path));
    htp_decode_path_inplace(cfg, tx, path);
    printf("After: %s\n\n", bstr_tocstr(path));

    //
    path = bstr_cstrdup("/One\\two///ThRee%2ffive%5csix/se%xxven/%u0074");
    cfg->path_case_insensitive = 1;
    cfg->path_compress_separators = 1;
    cfg->path_backslash_separators = 1;
    cfg->path_decode_separators = 1;
    cfg->path_invalid_encoding_handling = URL_DECODER_DECODE_INVALID;

    printf("Before: %s\n", bstr_tocstr(path));
    htp_decode_path_inplace(cfg, tx, path);
    printf("After: %s\n\n", bstr_tocstr(path));

    //
    path = bstr_cstrdup("/One\\two///ThRee%2ffive%5csix/se%xxven/%u0074%u0100");
    cfg->path_case_insensitive = 1;
    cfg->path_compress_separators = 1;
    cfg->path_backslash_separators = 1;
    cfg->path_decode_separators = 1;
    cfg->path_invalid_encoding_handling = URL_DECODER_PRESERVE_PERCENT;
    cfg->path_decode_u_encoding = 1;

    printf("Before: %s\n", bstr_tocstr(path));
    htp_decode_path_inplace(cfg, tx, path);
    printf("After: %s\n\n", bstr_tocstr(path));

    return (EXIT_SUCCESS);
}

void encode_utf8_2(uint8_t *data, uint32_t i) {
    i = i & 0x7ff;
    data[0] = 0xc0 + (i >> 6);
    data[1] = 0x80 + (i & 0x3f);
}

void encode_utf8_3(uint8_t *data, uint32_t i) {
    i = i & 0xffff;
    data[0] = 0xe0 + (i >> 12);
    data[1] = 0x80 + ((i >> 6) & 0x3f);
    data[2] = 0x80 + (i & 0x3f);
}

void encode_utf8_4(uint8_t *data, uint32_t i) {
    i = i & 0x10ffff;
    data[0] = 0xf0 + (i >> 18);
    data[1] = 0x80 + ((i >> 12) & 0x3f);
    data[2] = 0x80 + ((i >> 6) & 0x3f);
    data[3] = 0x80 + (i & 0x3f);
}

int main_utf8_decoder_tests(int argc, char** argv) {
    htp_cfg_t *cfg = htp_config_create();
    htp_tx_t *tx = htp_tx_create(cfg, 0, NULL);

    bstr *path = NULL;

    path = bstr_cstrdup("//////////");
    uint8_t *data = bstr_ptr(path);

    int i = 0;

    for (i = 0; i < 0x80; i++) {
        memset(data, 0x2f, 10);
        tx->flags = 0;
        encode_utf8_2(data, i);
        htp_utf8_validate_path(tx, path);
        if (tx->flags != HTP_PATH_UTF8_OVERLONG) {
            printf("#2 i %i data %x %x flags %x\n", i, (uint8_t) data[0], (uint8_t) data[1], tx->flags);
        }
    }

    for (i = 0; i < 0x800; i++) {
        memset(data, 0x2f, 10);
        tx->flags = 0;
        encode_utf8_3(data, i);
        htp_utf8_validate_path(tx, path);
        if (tx->flags != HTP_PATH_UTF8_OVERLONG) {
            printf("#3 i %x data %x %x %x flags %x\n", i, (uint8_t) data[0], (uint8_t) data[1], (uint8_t) data[2], tx->flags);
        }
    }

    for (i = 0; i < 0x10000; i++) {
        memset(data, 0x2f, 10);
        tx->flags = 0;
        encode_utf8_4(data, i);
        htp_utf8_validate_path(tx, path);
        if ((i >= 0xff00) && (i <= 0xffff)) {
            if (tx->flags != (HTP_PATH_UTF8_OVERLONG | HTP_PATH_FULLWIDTH_EVASION)) {
                printf("#4 i %x data %x %x %x %x flags %x\n", i, (uint8_t) data[0], (uint8_t) data[1], (uint8_t) data[2], (uint8_t) data[3], tx->flags);
            }
        } else {
            if (tx->flags != HTP_PATH_UTF8_OVERLONG) {
                printf("#4 i %x data %x %x %x %x flags %x\n", i, (uint8_t) data[0], (uint8_t) data[1], (uint8_t) data[2], (uint8_t) data[3], tx->flags);
            }
        }
    }
    return (EXIT_SUCCESS);
}

#define PATH_DECODE_TEST_BEFORE(NAME) \
    test_name = NAME; \
    tests++; \
    expected_status = 0; \
    expected_flags = -1; \
    success = 0; \
    cfg = htp_config_create(); \
    tx = htp_tx_create(cfg, 0, NULL);

#define PATH_DECODE_TEST_AFTER() \
    htp_decode_path_inplace(cfg, tx, input); \
    htp_utf8_decode_path_inplace(cfg, tx, input); \
    if (bstr_cmp(input, expected) == 0) success = 1; \
    printf("[%2i] %s: %s\n", tests, (success == 1 ? "SUCCESS" : "FAILURE"), test_name); \
    if ((success == 0)||((expected_status != 0)&&(expected_status != tx->response_status_expected_number))) { \
        char *s1 = bstr_tocstr(input); \
        char *s2 = bstr_tocstr(expected); \
        printf("      Output: [%s]\n", s1); \
        printf("    Expected: [%s]\n", s2); \
        if (expected_status != 0) { \
            printf("    Expected status %i; got %i\n", expected_status, tx->response_status_expected_number); \
        } \
        if (expected_flags != -1) { \
            printf("    Expected flags 0x%x; got 0x%x\n", expected_flags, tx->flags); \
        } \
        free(s2); \
        free(s1); \
        failures++; \
    } \
    htp_tx_destroy(tx); \
    htp_config_destroy(cfg); \
    bstr_free(expected); \
    bstr_free(input);


int main_path_tests(int argc, char** argv) {
    htp_cfg_t *cfg = NULL;
    htp_tx_t *tx = NULL;
    bstr *input = NULL;
    bstr *expected = NULL;
    int success = 0;
    int tests = 0;
    int failures = 0;        
    int expected_status = 0;
    int expected_flags = 0;
    char *test_name = NULL;
    
    PATH_DECODE_TEST_BEFORE("URL-decoding");
    input = bstr_cstrdup("/%64est");
    expected = bstr_cstrdup("/dest");    
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("Invalid URL-encoded, preserve %");
    input = bstr_cstrdup("/%xxest");
    expected = bstr_cstrdup("/%xxest");
    expected_flags = HTP_PATH_INVALID_ENCODING;
    cfg->path_invalid_encoding_handling = URL_DECODER_PRESERVE_PERCENT;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("Invalid URL-encoded, remove %");
    input = bstr_cstrdup("/%xxest");
    expected = bstr_cstrdup("/xxest");
    expected_flags = HTP_PATH_INVALID_ENCODING;
    cfg->path_invalid_encoding_handling = URL_DECODER_REMOVE_PERCENT;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("Invalid URL-encoded (end of string, test 1), preserve %");
    input = bstr_cstrdup("/test/%2");
    expected = bstr_cstrdup("/test/%2");
    expected_flags = HTP_PATH_INVALID_ENCODING;
    cfg->path_invalid_encoding_handling = URL_DECODER_PRESERVE_PERCENT;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("Invalid URL-encoded (end of string, test 2), preserve %");
    input = bstr_cstrdup("/test/%");
    expected = bstr_cstrdup("/test/%");
    expected_flags = HTP_PATH_INVALID_ENCODING;
    cfg->path_invalid_encoding_handling = URL_DECODER_PRESERVE_PERCENT;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("Invalid URL-encoded, preserve % and 400");
    input = bstr_cstrdup("/%xxest");
    expected = bstr_cstrdup("/%xxest");
    expected_status = 400;
    expected_flags = HTP_PATH_INVALID_ENCODING;
    cfg->path_invalid_encoding_handling = URL_DECODER_STATUS_400;    
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("%u decoding (expected not to decode; 400)");
    input = bstr_cstrdup("/%u0064");
    expected = bstr_cstrdup("/%u0064");
    expected_flags = HTP_PATH_INVALID_ENCODING;
    expected_status = 400;
    cfg->path_invalid_encoding_handling = URL_DECODER_STATUS_400;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("%u decoding (decode; 400)");
    input = bstr_cstrdup("/%u0064");
    expected = bstr_cstrdup("/d");
    expected_status = 400;
    expected_flags = HTP_PATH_OVERLONG_U;
    cfg->path_decode_u_encoding = STATUS_400;    
    PATH_DECODE_TEST_AFTER();   

    PATH_DECODE_TEST_BEFORE("%u decoding (also overlong)");
    input = bstr_cstrdup("/%u0064");
    expected = bstr_cstrdup("/d");
    expected_flags = HTP_PATH_OVERLONG_U;
    cfg->path_decode_u_encoding = YES;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("Invalid %u decoding, leave; preserve percent");
    input = bstr_cstrdup("/%uXXXX---");
    expected = bstr_cstrdup("/%uXXXX---");
    expected_flags = HTP_PATH_INVALID_ENCODING;
    cfg->path_decode_u_encoding = YES;
    cfg->path_invalid_encoding_handling = URL_DECODER_PRESERVE_PERCENT;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("Invalid %u decoding, decode invalid; preserve percent");
    input = bstr_cstrdup("/%uXXXX---");
    expected = bstr_cstrdup("/?---");
    expected_flags = HTP_PATH_INVALID_ENCODING;
    cfg->path_decode_u_encoding = YES;
    cfg->path_invalid_encoding_handling = URL_DECODER_DECODE_INVALID;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("Invalid %u decoding, decode invalid; preserve percent; 400");
    input = bstr_cstrdup("/%uXXXX---");
    expected = bstr_cstrdup("/?---");
    expected_flags = HTP_PATH_INVALID_ENCODING;
    expected_status = 400;
    cfg->path_decode_u_encoding = YES;
    cfg->path_invalid_encoding_handling = URL_DECODER_STATUS_400;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("Invalid %u decoding (not enough data 1), preserve percent");
    input = bstr_cstrdup("/%u123");
    expected = bstr_cstrdup("/%u123");
    expected_flags = HTP_PATH_INVALID_ENCODING;
    cfg->path_decode_u_encoding = YES;
    cfg->path_invalid_encoding_handling = URL_DECODER_PRESERVE_PERCENT;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("Invalid %u decoding (not enough data 2), preserve percent");
    input = bstr_cstrdup("/%u12");
    expected = bstr_cstrdup("/%u12");
    expected_flags = HTP_PATH_INVALID_ENCODING;
    cfg->path_decode_u_encoding = YES;
    cfg->path_invalid_encoding_handling = URL_DECODER_PRESERVE_PERCENT;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("Invalid %u decoding (not enough data 3), preserve percent");
    input = bstr_cstrdup("/%u1");
    expected = bstr_cstrdup("/%u1");
    expected_flags = HTP_PATH_INVALID_ENCODING;
    cfg->path_decode_u_encoding = YES;
    cfg->path_invalid_encoding_handling = URL_DECODER_PRESERVE_PERCENT;
    PATH_DECODE_TEST_AFTER();  

    PATH_DECODE_TEST_BEFORE("%u decoding, best-fit mapping");
    input = bstr_cstrdup("/%u0107");
    expected = bstr_cstrdup("/c");    
    cfg->path_decode_u_encoding = YES;
    cfg->path_unicode_mapping = BESTFIT;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("%u decoding, 404 to UCS-2 characters");
    input = bstr_cstrdup("/%u0107");
    expected = bstr_cstrdup("/c");
    expected_status = 404;
    cfg->path_decode_u_encoding = YES;
    cfg->path_unicode_mapping = STATUS_404;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("Forward slash (URL-encoded), not expect to decode");
    input = bstr_cstrdup("/one%2ftwo");
    expected = bstr_cstrdup("/one%2ftwo");
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("Forward slash (URL-encoded), expect to decode");
    input = bstr_cstrdup("/one%2ftwo");
    expected = bstr_cstrdup("/one/two");
    cfg->path_decode_separators = YES;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("Forward slash (URL-encoded), expect not do decode and 404");
    input = bstr_cstrdup("/one%2ftwo");
    expected = bstr_cstrdup("/one%2ftwo");
    expected_status = 404;
    cfg->path_decode_separators = STATUS_404;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("Forward slash (%u-encoded), expect to decode");
    input = bstr_cstrdup("/one%u002ftwo");
    expected = bstr_cstrdup("/one/two");    
    cfg->path_decode_separators = YES;
    cfg->path_decode_u_encoding = YES;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("Forward slash (%u-encoded, fullwidth), expect to decode");
    input = bstr_cstrdup("/one%uff0ftwo");
    expected = bstr_cstrdup("/one/two");
    cfg->path_decode_separators = YES;
    cfg->path_decode_u_encoding = YES;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("Backslash (URL-encoded), not a separator; expect to decode");
    input = bstr_cstrdup("/one%5ctwo");
    expected = bstr_cstrdup("/one\\two");
    cfg->path_decode_separators = YES;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("Backslash (URL-encoded), as path segment separator");
    input = bstr_cstrdup("/one%5ctwo");
    expected = bstr_cstrdup("/one/two");
    cfg->path_decode_separators = YES;
    cfg->path_backslash_separators = 1;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("Backslash (not encoded), as path segment separator");
    input = bstr_cstrdup("/one\\two");
    expected = bstr_cstrdup("/one/two");    
    cfg->path_backslash_separators = YES;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("Backslash (%u-encoded), as path segment separator");
    input = bstr_cstrdup("/one%u005ctwo");
    expected = bstr_cstrdup("/one/two");
    cfg->path_decode_separators = YES;
    cfg->path_backslash_separators = YES;
    cfg->path_decode_u_encoding = YES;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("Backslash (%u-encoded, fullwidth), as path segment separator");
    input = bstr_cstrdup("/one%uff3ctwo");
    expected = bstr_cstrdup("/one/two");
    cfg->path_decode_separators = YES;
    cfg->path_backslash_separators = 1;
    cfg->path_decode_u_encoding = YES;
    PATH_DECODE_TEST_AFTER();    

    PATH_DECODE_TEST_BEFORE("Invalid UTF-8 encoding, encoded");
    input = bstr_cstrdup("/%f7test");
    expected = bstr_cstrdup("/\xf7test");
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("Invalid UTF-8 encoding, encoded (400)");
    input = bstr_cstrdup("/%f7test");
    expected = bstr_cstrdup("/\xf7test");
    expected_status = 400;
    expected_flags = HTP_PATH_UTF8_INVALID;
    cfg->path_invalid_utf8_handling = STATUS_400;
    PATH_DECODE_TEST_AFTER();   

    PATH_DECODE_TEST_BEFORE("NUL byte (raw) in path; leave");
    input = bstr_memdup("/test\0text", 10);
    expected = bstr_memdup("/test\0text", 10);
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("NUL byte (raw) in path; terminate path");
    input = bstr_memdup("/test\0text", 10);
    expected = bstr_cstrdup("/test");
    cfg->path_nul_raw_handling = TERMINATE;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("NUL byte (raw) in path; 400");
    input = bstr_memdup("/test\0text", 10);
    expected = bstr_memdup("/test\0text", 10);
    cfg->path_nul_raw_handling = STATUS_400;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("NUL byte (URL-encoded) in path; leave");
    input = bstr_cstrdup("/test%00text");
    expected = bstr_memdup("/test\0text", 10);
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("NUL byte (URL-encoded) in path; terminate path");
    input = bstr_cstrdup("/test%00text");
    expected = bstr_cstrdup("/test");
    cfg->path_nul_encoded_handling = TERMINATE;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("NUL byte (URL-encoded) in path; 400");
    input = bstr_cstrdup("/test%00text");
    expected = bstr_memdup("/test\0text", 10);
    cfg->path_nul_encoded_handling = STATUS_400;
    expected_status = 400;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("NUL byte (URL-encoded) in path; 404");
    input = bstr_cstrdup("/test%00text");
    expected = bstr_memdup("/test\0text", 10);
    cfg->path_nul_encoded_handling = STATUS_404;
    expected_status = 404;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("NUL byte (%u-encoded) in path; terminate path");
    input = bstr_cstrdup("/test%00text");
    expected = bstr_cstrdup("/test");
    cfg->path_nul_encoded_handling = TERMINATE;
    cfg->path_decode_u_encoding = YES;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("NUL byte (%u-encoded) in path; 400");
    input = bstr_cstrdup("/test%00text");
    expected = bstr_memdup("/test\0text", 10);
    cfg->path_nul_encoded_handling = STATUS_400;
    cfg->path_decode_u_encoding = YES;
    expected_status = 400;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("NUL byte (%u-encoded) in path; 404");
    input = bstr_cstrdup("/test%00text");
    expected = bstr_memdup("/test\0text", 10);
    cfg->path_nul_encoded_handling = STATUS_404;
    cfg->path_decode_u_encoding = YES;
    expected_status = 404;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("Control char in path, encoded (no effect)");
    input = bstr_cstrdup("/%01test");
    expected = bstr_cstrdup("/\x01test");
    cfg->path_control_char_handling = NONE;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("Control char in path, raw (no effect)");
    input = bstr_cstrdup("/\x01test");
    expected = bstr_cstrdup("/\x01test");
    cfg->path_control_char_handling = NONE;
    PATH_DECODE_TEST_AFTER();
    
    PATH_DECODE_TEST_BEFORE("Control char in path, encoded (400)");
    input = bstr_cstrdup("/%01test");
    expected = bstr_cstrdup("/\x01test");
    expected_status = 400;
    cfg->path_control_char_handling = STATUS_400;    
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("Control char in path, raw (400)");
    input = bstr_cstrdup("/\x01test");
    expected = bstr_cstrdup("/\x01test");
    expected_status = 400;
    cfg->path_control_char_handling = STATUS_400;
    PATH_DECODE_TEST_AFTER();    

    PATH_DECODE_TEST_BEFORE("UTF-8; overlong 2-byte sequence");
    input = bstr_cstrdup("/%c1%b4est");
    expected = bstr_cstrdup("/test");
    expected_flags = HTP_PATH_UTF8_OVERLONG;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("UTF-8; overlong 3-byte sequence");
    input = bstr_cstrdup("/%e0%81%b4est");
    expected = bstr_cstrdup("/test");
    expected_flags = HTP_PATH_UTF8_OVERLONG;
    PATH_DECODE_TEST_AFTER();

    PATH_DECODE_TEST_BEFORE("UTF-8; overlong 4-byte sequence");
    input = bstr_cstrdup("/%f0%80%81%b4est");
    expected = bstr_cstrdup("/test");
    expected_flags = HTP_PATH_UTF8_OVERLONG;
    PATH_DECODE_TEST_AFTER();

    printf("\n");
    printf("Total tests: %i, %i failure(s).\n", tests, failures);

    return (EXIT_SUCCESS);
}
