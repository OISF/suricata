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

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include "../htp/htp.h"
#include "test.h"

/**
 * Destroys a test.
 *
 * @param test
 */
static void test_destroy(test_t *test) {
    if (test->buf != NULL) {
        free(test->buf);
        test->buf = NULL;
    }
}

/**
 * Checks if there's a chunk boundary at the given position.
 *
 * @param test
 * @param pos
 * @return Zero if there is no boundary, SERVER or CLIENT if a boundary
 *         was found, and a negative value on error (e.g., not enough data
 *         to determine if a boundary is present).
 */
static int test_is_boundary(test_t *test, int pos) {
    // Check that there's enough room
    if (pos + 3 >= test->len) return -1;

    if ((test->buf[pos] == '<') && (test->buf[pos + 1] == '<') && (test->buf[pos + 2] == '<')) {
        if (test->buf[pos + 3] == '\n') {
            return SERVER;
        }

        if (test->buf[pos + 3] == '\r') {
            if (pos + 4 >= test->len) return -1;
            else if (test->buf[pos + 4] == '\n') {
                return SERVER;
            }
        }
    }

    if ((test->buf[pos] == '>') && (test->buf[pos + 1] == '>') && (test->buf[pos + 2] == '>')) {
        if (test->buf[pos + 3] == '\n') {
            return CLIENT;
        }

        if (test->buf[pos + 3] == '\r') {
            if (pos + 4 >= test->len) return -1;
            else if (test->buf[pos + 4] == '\n') {
                return CLIENT;
            }
        }
    }

    return 0;
}

/**
 * Initializes test by loading the entire data file into a memory block.
 *
 * @param test
 * @param filename
 * @return Non-negative value on success, negative value on error.
 */
static int test_init(test_t *test, const char *filename) {
    memset(test, 0, sizeof (test_t));

    int fd = open(filename, O_RDONLY | O_BINARY);
    if (fd < 0) return -1;

    struct stat buf;
    if (fstat(fd, &buf) < 0) {
        return -1;
    }

    test->buf = malloc(buf.st_size);
    test->len = 0;
    test->pos = 0;

    int bytes_read = 0;
    while ((bytes_read = read(fd, test->buf + test->len, buf.st_size - test->len)) > 0) {
        test->len += bytes_read;
    }

    if (test->len != buf.st_size) {
        free(test->buf);
        return -2;
    }

    close(fd);

    return 1;
}

void test_start(test_t *test) {
    test->pos = 0;
}

/**
 * Finds the next data chunk in the given test.
 *
 * @param test
 * @return One if a chunk is found or zero if there are no more chunks in the test. On
 *         success, test->chunk will point to the beginning of the chunk, while
 *         test->chunk_len will contain its length.
 */
static int test_next_chunk(test_t *test) {
    if (test->pos >= test->len) {
        return 0;
    }

    test->chunk = NULL;

    while (test->pos < test->len) {
        // Do we need to start another chunk?
        if (test->chunk == NULL) {
            // Are we at a boundary
            test->chunk_direction = test_is_boundary(test, test->pos);
            if (test->chunk_direction <= 0) {
                // Error
                return -1;
            }

            // Move over the boundary
            test->pos += 4;
            if (test->buf[test->pos] == '\n') test->pos++;

            // Start new chunk
            test->chunk = test->buf + test->pos;
            test->chunk_offset = test->pos;
        }

        // Are we at the end of a line?
        if (test->buf[test->pos] == '\n') {
            int r = test_is_boundary(test, test->pos + 1);
            if ((r == CLIENT) || (r == SERVER)) {
                // We got ourselves a chunk
                test->chunk_len = test->pos - test->chunk_offset;

                // Remove one '\r' (in addition to the '\n' that we've already removed),
                // which belongs to the next boundary
                if ((test->chunk_len > 0) && (test->chunk[test->chunk_len - 1] == '\r')) {
                    test->chunk_len--;
                }

                // Position at the next boundary line
                test->pos++;

                return 1;
            }
        }

        test->pos++;
    }


    if (test->chunk != NULL) {
        test->chunk_len = test->pos - test->chunk_offset;
        return 1;
    }

    return 0;
}

static int parse_filename(const char *filename, char **remote_addr, int *remote_port, char **local_addr, int *local_port) {
    char *copy = strdup(filename);
    char *p, *saveptr;

    char *start = copy;
    char *q = strrchr(copy, '/');
    if (q != NULL) start = q;

    q = strrchr(start, '\\');
    if (q != NULL) start = q;

    int count = 0;
    p = strtok_r(start, "_", &saveptr);
    while (p != NULL) {
        count++;
        // printf("%i %s\n", count, p);

        switch (count) {
            case 2:
                *remote_addr = strdup(p);
                break;
            case 3:
                *remote_port = atoi(p);
                break;
            case 4:
                *local_addr = strdup(p);
            case 5:
                *local_port = atoi(p);
                break;
        }

        p = strtok_r(NULL, "_", &saveptr);
    }

    free(copy);

    return 0;
}

/**
 * Runs a single test.
 *
 * @param filename
 * @param cfg
 * @return A pointer to the instance of htp_connp_t created during
 *         the test, or NULL if the test failed for some reason.
 */
int test_run(const char *testsdir, const char *testname, htp_cfg_t *cfg, htp_connp_t **connp) {
    char filename[1025];
    test_t test;
    struct timeval tv_start, tv_end;
    int rc;

    *connp = NULL;

    strncpy(filename, testsdir, 1024);
    strncat(filename, "/", 1024 - strlen(filename));
    strncat(filename, testname, 1024 - strlen(filename));

    printf("Filename: %s\n", filename);

    // Initinialize test

    rc = test_init(&test, filename);
    if (rc < 0) {
        return rc;
    }

    gettimeofday(&tv_start, NULL);

    test_start(&test);

    // Create parser
    *connp = htp_connp_create(cfg);
    if (*connp == NULL) {
        fprintf(stderr, "Failed to create connection parser\n");
        exit(1);
    }

    htp_connp_set_user_data(*connp, (void *) 0x02);

    // Does the filename contain connection metdata?
    if (strncmp(testname, "stream", 6) == 0) {
        // It does; use it
        char *remote_addr, *local_addr;
        int remote_port, local_port;

        parse_filename(testname, &remote_addr, &remote_port, &local_addr, &local_port);
        htp_connp_open(*connp, (const char *) remote_addr, remote_port, (const char *) local_addr, local_port, tv_start.tv_usec);
        free(remote_addr);
        free(local_addr);
    } else {
        // No connection metadata; provide some fake information instead
        htp_connp_open(*connp, (const char *) "127.0.0.1", 10000, (const char *) "127.0.0.1", 80, tv_start.tv_usec);
    }

    // Find all chunks and feed them to the parser
    int in_data_other = 0;
    char *in_data;
    size_t in_data_len;
    size_t in_data_offset;

    int out_data_other = 0;
    char *out_data;
    size_t out_data_len;
    size_t out_data_offset;

    for (;;) {
        if (test_next_chunk(&test) <= 0) {
            break;
        }

        if (test.chunk_direction == CLIENT) {
            if (in_data_other) {
                test_destroy(&test);
                fprintf(stderr, "Unable to buffer more than one inbound chunk.\n");
                return -1;
            }

            int rc = htp_connp_req_data(*connp, tv_start.tv_usec, test.chunk, test.chunk_len);
            if (rc == STREAM_STATE_ERROR) {
                test_destroy(&test);
                return -101;
            }
            if (rc == STREAM_STATE_DATA_OTHER) {
                // Parser needs to see the outbound stream in order to continue
                // parsing the inbound stream.
                in_data_other = 1;
                in_data = test.chunk;
                in_data_len = test.chunk_len;
                in_data_offset = htp_connp_req_data_consumed(*connp);                
            }
        } else {
            if (out_data_other) {
                int rc = htp_connp_res_data(*connp, tv_start.tv_usec, out_data + out_data_offset, out_data_len - out_data_offset);
                if (rc == STREAM_STATE_ERROR) {
                    test_destroy(&test);
                    return -104;
                }
                out_data_other = 0;
            }

            int rc = htp_connp_res_data(*connp, tv_start.tv_usec, test.chunk, test.chunk_len);
            if (rc == STREAM_STATE_ERROR) {
                test_destroy(&test);
                return -102;
            }
            if (rc == STREAM_STATE_DATA_OTHER) {
                // Parser needs to see the outbound stream in order to continue
                // parsing the inbound stream.
                out_data_other = 1;
                out_data = test.chunk;
                out_data_len = test.chunk_len;
                out_data_offset = htp_connp_res_data_consumed(*connp);
                // printf("# YYY out offset is %d\n", out_data_offset);
            }

            if (in_data_other) {
                int rc = htp_connp_req_data(*connp, tv_start.tv_usec, in_data + in_data_offset, in_data_len - in_data_offset);
                if (rc == STREAM_STATE_ERROR) {
                    test_destroy(&test);
                    return -103;
                }
                in_data_other = 0;
            }
        }
    }

    if (out_data_other) {
        int rc = htp_connp_res_data(*connp, tv_start.tv_usec, out_data + out_data_offset, out_data_len - out_data_offset);
        if (rc == STREAM_STATE_ERROR) {
            test_destroy(&test);
            return -104;
        }
        out_data_other = 0;
    }

    gettimeofday(&tv_end, NULL);

    // Close the connection
    htp_connp_close(*connp, tv_end.tv_usec);

    // printf("Parsing time: %i\n", tv_end.tv_usec - tv_start.tv_usec);

    // Clean up
    test_destroy(&test);

    return 1;
}
