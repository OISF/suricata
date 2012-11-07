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

#include "htp.h"

// NOTE The parser contains a lot of duplicated code. That is on purpose.
//
//      Within the request parser alone there are several states in which
//      bytes are copied into the line buffer and lines are processed one at a time.
//      This code could be made more elegant by adding a new line-reading state along
//      with a what-fn-to-invoke-to-handle-line pointer.
//
//      Furthermore, the entire request parser is terribly similar to the response parser.
//      It is imaginable that a single parser could handle both.
//
//      After some thought, I decided not to make any changes (at least not for the time
//      being). State-based parsers are sometimes difficult to understand. I remember trying
//      to figure one once and I had a hard time following the logic because each function
//      was small and did exactly one thing. There was jumping all around. You could probably
//      say that it was elegant, but I saw it as difficult to understand, verify and maintain.
//
//      Thus, I am keeping this inelegant but quite straightforward parser with duplicated code,
//      mostly for the sake of maintenance.
//
//      For the time being, anyway. I will review at a later time.

/**
 * Clears an existing parser error, if any.
 *
 * @param connp
 */
void htp_connp_clear_error(htp_connp_t *connp) {
    connp->last_error = NULL;
}

/**
 * Closes the connection associated with the supplied parser.
 *
 * @param connp
 * @param timestamp
 */
void htp_connp_close(htp_connp_t *connp, htp_time_t timestamp) {
    // Update internal information
    connp->conn->close_timestamp = timestamp;
    connp->in_status = STREAM_STATE_CLOSED;
    connp->out_status = STREAM_STATE_CLOSED;

    // Call the parsers one last time, which will allow them
    // to process the events that depend on stream closure
    htp_connp_req_data(connp, timestamp, NULL, 0);
    htp_connp_res_data(connp, timestamp, NULL, 0);
}

/**
 * Creates a new connection parser using the provided configuration. Because
 * the configuration structure is used directly, in a multithreaded environment
 * you are not allowed to change the structure, ever. If you have a need to
 * change configuration on per-connection basis, make a copy of the configuration
 * structure to go along with every connection parser.
 *
 * @param cfg
 * @return A pointer to a newly created htp_connp_t instance.
 */
htp_connp_t *htp_connp_create(htp_cfg_t *cfg) {
    htp_connp_t *connp = calloc(1, sizeof (htp_connp_t));
    if (connp == NULL) return NULL;

    // Use the supplied configuration structure
    connp->cfg = cfg;

    // Create a new connection object
    connp->conn = htp_conn_create(connp);
    if (connp->conn == NULL) {
        free(connp);
        return NULL;
    }

    connp->in_status = HTP_OK;

    // Request parsing

    connp->in_line_size = cfg->field_limit_hard;
    connp->in_line_len = 0;
    connp->in_line = malloc(connp->in_line_size);
    if (connp->in_line == NULL) {
        htp_conn_destroy(connp->conn);
        free(connp);
        return NULL;
    }

    connp->in_header_line_index = -1;
    connp->in_state = htp_connp_REQ_IDLE;

    // Response parsing

    connp->out_line_size = cfg->field_limit_hard;
    connp->out_line_len = 0;
    connp->out_line = malloc(connp->out_line_size);
    if (connp->out_line == NULL) {
        free(connp->in_line);
        htp_conn_destroy(connp->conn);
        free(connp);
        return NULL;
    }

    connp->out_header_line_index = -1;
    connp->out_state = htp_connp_RES_IDLE;

    connp->in_status = STREAM_STATE_NEW;
    connp->out_status = STREAM_STATE_NEW;

    return connp;
}

/**
 * Creates a new configuration parser, making a copy of the supplied
 * configuration structure.
 *
 * @param cfg
 * @return A pointer to a newly created htp_connp_t instance.
 */
htp_connp_t *htp_connp_create_copycfg(htp_cfg_t *cfg) {
    htp_connp_t *connp = htp_connp_create(cfg);
    if (connp == NULL) return NULL;

    connp->cfg = htp_config_copy(cfg);
    if (connp->cfg == NULL) {
        htp_connp_destroy(connp);
        return NULL;
    }

    connp->is_cfg_private = 1;

    return connp;
}

/**
 * Destroys the connection parser and its data structures, leaving
 * the connection data intact.
 *
 * @param connp
 */
void htp_connp_destroy(htp_connp_t *connp) {
    if (connp == NULL)
        return;

    if (connp->out_decompressor != NULL) {
        connp->out_decompressor->destroy(connp->out_decompressor);
        connp->out_decompressor = NULL;
    }

    if (connp->in_header_line != NULL) {
        if (connp->in_header_line->line != NULL) {
            free(connp->in_header_line->line);
        }

        free(connp->in_header_line);
    }

    if (connp->in_line != NULL)
        free(connp->in_line);

    if (connp->out_header_line != NULL) {
        if (connp->out_header_line->line != NULL) {
            free(connp->out_header_line->line);
        }

        free(connp->out_header_line);
    }

    if (connp->out_line != NULL)
        free(connp->out_line);

    // Destroy the configuration structure, but only
    // if it is our private copy
    if ((connp->is_cfg_private) && (connp->cfg != NULL)) {
        htp_config_destroy(connp->cfg);
    }

    free(connp);
}

/**
 * Destroys the connection parser, its data structures, as well
 * as the connection and its transactions.
 *
 * @param connp
 */
void htp_connp_destroy_all(htp_connp_t *connp) {
    if (connp == NULL)
        return;

    if (connp->conn != NULL) {
        // Destroy connection
        htp_conn_destroy(connp->conn);
        connp->conn = NULL;
    }

    // Destroy everything else
    htp_connp_destroy(connp);
}

/**
 * Retrieve the user data associated with this connection parser.
 * 
 * @param connp
 * @return User data, or NULL if there isn't any.
 */
void *htp_connp_get_data(htp_connp_t *connp) {
    return connp->user_data;
}

/**
 * Returns the last error that occured with this connection parser. Do note, however,
 * that the value in this field will only be valid immediately after an error condition,
 * but it is not guaranteed to remain valid if the parser is invoked again.
 *
 * @param connp
 * @return A pointer to an htp_log_t instance if there is an error, or NULL
 *         if there isn't.
 */
htp_log_t *htp_connp_get_last_error(htp_connp_t *connp) {
    return connp->last_error;
}

/**
 * Opens connection.
 *
 * @param connp
 * @param remote_addr Remote address
 * @param remote_port Remote port
 * @param local_addr Local address
 * @param local_port Local port
 * @param timestamp
 */
void htp_connp_open(htp_connp_t *connp, const char *remote_addr, int remote_port, const char *local_addr, int local_port, htp_time_t timestamp) {
    if ((connp->in_status != STREAM_STATE_NEW) || (connp->out_status != STREAM_STATE_NEW)) {
        htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "Connection is already open");
        return;
    }

    if (remote_addr != NULL) {
        connp->conn->remote_addr = strdup(remote_addr);
        if (connp->conn->remote_addr == NULL) return;
    }

    connp->conn->remote_port = remote_port;

    if (local_addr != NULL) {
        connp->conn->local_addr = strdup(local_addr);
        if (connp->conn->local_addr == NULL) {
            if (connp->conn->remote_addr != NULL) {
                free(connp->conn->remote_addr);
            }
            return;
        }
    }

    connp->conn->local_port = local_port;
    connp->conn->open_timestamp = timestamp;
    connp->in_status = STREAM_STATE_OPEN;
    connp->out_status = STREAM_STATE_OPEN;
}

/**
 * Associate user data with the supplied parser.
 *
 * @param connp
 * @param user_data
 */
void htp_connp_set_user_data(htp_connp_t *connp, void *user_data) {
    connp->user_data = user_data;
}

void *htp_connp_get_user_data(htp_connp_t *connp) {
    return(connp->user_data);
}
