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

/**
 * This map is used by default for best-fit mapping from the Unicode
 * values U+0100-FFFF.
 */
static unsigned char bestfit_1252[] =
{ 0x01, 0x00, 0x41, 0x01, 0x01, 0x61, 0x01, 0x02, 0x41, 0x01, 0x03, 0x61,
  0x01, 0x04, 0x41, 0x01, 0x05, 0x61, 0x01, 0x06, 0x43, 0x01, 0x07, 0x63,
  0x01, 0x08, 0x43, 0x01, 0x09, 0x63, 0x01, 0x0a, 0x43, 0x01, 0x0b, 0x63,
  0x01, 0x0c, 0x43, 0x01, 0x0d, 0x63, 0x01, 0x0e, 0x44, 0x01, 0x0f, 0x64,
  0x01, 0x11, 0x64, 0x01, 0x12, 0x45, 0x01, 0x13, 0x65, 0x01, 0x14, 0x45,
  0x01, 0x15, 0x65, 0x01, 0x16, 0x45, 0x01, 0x17, 0x65, 0x01, 0x18, 0x45,
  0x01, 0x19, 0x65, 0x01, 0x1a, 0x45, 0x01, 0x1b, 0x65, 0x01, 0x1c, 0x47,
  0x01, 0x1d, 0x67, 0x01, 0x1e, 0x47, 0x01, 0x1f, 0x67, 0x01, 0x20, 0x47,
  0x01, 0x21, 0x67, 0x01, 0x22, 0x47, 0x01, 0x23, 0x67, 0x01, 0x24, 0x48,
  0x01, 0x25, 0x68, 0x01, 0x26, 0x48, 0x01, 0x27, 0x68, 0x01, 0x28, 0x49,
  0x01, 0x29, 0x69, 0x01, 0x2a, 0x49, 0x01, 0x2b, 0x69, 0x01, 0x2c, 0x49,
  0x01, 0x2d, 0x69, 0x01, 0x2e, 0x49, 0x01, 0x2f, 0x69, 0x01, 0x30, 0x49,
  0x01, 0x31, 0x69, 0x01, 0x34, 0x4a, 0x01, 0x35, 0x6a, 0x01, 0x36, 0x4b,
  0x01, 0x37, 0x6b, 0x01, 0x39, 0x4c, 0x01, 0x3a, 0x6c, 0x01, 0x3b, 0x4c,
  0x01, 0x3c, 0x6c, 0x01, 0x3d, 0x4c, 0x01, 0x3e, 0x6c, 0x01, 0x41, 0x4c,
  0x01, 0x42, 0x6c, 0x01, 0x43, 0x4e, 0x01, 0x44, 0x6e, 0x01, 0x45, 0x4e,
  0x01, 0x46, 0x6e, 0x01, 0x47, 0x4e, 0x01, 0x48, 0x6e, 0x01, 0x4c, 0x4f,
  0x01, 0x4d, 0x6f, 0x01, 0x4e, 0x4f, 0x01, 0x4f, 0x6f, 0x01, 0x50, 0x4f,
  0x01, 0x51, 0x6f, 0x01, 0x54, 0x52, 0x01, 0x55, 0x72, 0x01, 0x56, 0x52,
  0x01, 0x57, 0x72, 0x01, 0x58, 0x52, 0x01, 0x59, 0x72, 0x01, 0x5a, 0x53,
  0x01, 0x5b, 0x73, 0x01, 0x5c, 0x53, 0x01, 0x5d, 0x73, 0x01, 0x5e, 0x53,
  0x01, 0x5f, 0x73, 0x01, 0x62, 0x54, 0x01, 0x63, 0x74, 0x01, 0x64, 0x54,
  0x01, 0x65, 0x74, 0x01, 0x66, 0x54, 0x01, 0x67, 0x74, 0x01, 0x68, 0x55,
  0x01, 0x69, 0x75, 0x01, 0x6a, 0x55, 0x01, 0x6b, 0x75, 0x01, 0x6c, 0x55,
  0x01, 0x6d, 0x75, 0x01, 0x6e, 0x55, 0x01, 0x6f, 0x75, 0x01, 0x70, 0x55,
  0x01, 0x71, 0x75, 0x01, 0x72, 0x55, 0x01, 0x73, 0x75, 0x01, 0x74, 0x57,
  0x01, 0x75, 0x77, 0x01, 0x76, 0x59, 0x01, 0x77, 0x79, 0x01, 0x79, 0x5a,
  0x01, 0x7b, 0x5a, 0x01, 0x7c, 0x7a, 0x01, 0x80, 0x62, 0x01, 0x97, 0x49,
  0x01, 0x9a, 0x6c, 0x01, 0x9f, 0x4f, 0x01, 0xa0, 0x4f, 0x01, 0xa1, 0x6f,
  0x01, 0xab, 0x74, 0x01, 0xae, 0x54, 0x01, 0xaf, 0x55, 0x01, 0xb0, 0x75,
  0x01, 0xb6, 0x7a, 0x01, 0xc0, 0x7c, 0x01, 0xc3, 0x21, 0x01, 0xcd, 0x41,
  0x01, 0xce, 0x61, 0x01, 0xcf, 0x49, 0x01, 0xd0, 0x69, 0x01, 0xd1, 0x4f,
  0x01, 0xd2, 0x6f, 0x01, 0xd3, 0x55, 0x01, 0xd4, 0x75, 0x01, 0xd5, 0x55,
  0x01, 0xd6, 0x75, 0x01, 0xd7, 0x55, 0x01, 0xd8, 0x75, 0x01, 0xd9, 0x55,
  0x01, 0xda, 0x75, 0x01, 0xdb, 0x55, 0x01, 0xdc, 0x75, 0x01, 0xde, 0x41,
  0x01, 0xdf, 0x61, 0x01, 0xe4, 0x47, 0x01, 0xe5, 0x67, 0x01, 0xe6, 0x47,
  0x01, 0xe7, 0x67, 0x01, 0xe8, 0x4b, 0x01, 0xe9, 0x6b, 0x01, 0xea, 0x4f,
  0x01, 0xeb, 0x6f, 0x01, 0xec, 0x4f, 0x01, 0xed, 0x6f, 0x01, 0xf0, 0x6a,
  0x02, 0x61, 0x67, 0x02, 0xb9, 0x27, 0x02, 0xba, 0x22, 0x02, 0xbc, 0x27,
  0x02, 0xc4, 0x5e, 0x02, 0xc8, 0x27, 0x02, 0xcb, 0x60, 0x02, 0xcd, 0x5f,
  0x03, 0x00, 0x60, 0x03, 0x02, 0x5e, 0x03, 0x03, 0x7e, 0x03, 0x0e, 0x22,
  0x03, 0x31, 0x5f, 0x03, 0x32, 0x5f, 0x03, 0x7e, 0x3b, 0x03, 0x93, 0x47,
  0x03, 0x98, 0x54, 0x03, 0xa3, 0x53, 0x03, 0xa6, 0x46, 0x03, 0xa9, 0x4f,
  0x03, 0xb1, 0x61, 0x03, 0xb4, 0x64, 0x03, 0xb5, 0x65, 0x03, 0xc0, 0x70,
  0x03, 0xc3, 0x73, 0x03, 0xc4, 0x74, 0x03, 0xc6, 0x66, 0x04, 0xbb, 0x68,
  0x05, 0x89, 0x3a, 0x06, 0x6a, 0x25, 0x20, 0x00, 0x20, 0x20, 0x01, 0x20,
  0x20, 0x02, 0x20, 0x20, 0x03, 0x20, 0x20, 0x04, 0x20, 0x20, 0x05, 0x20,
  0x20, 0x06, 0x20, 0x20, 0x10, 0x2d, 0x20, 0x11, 0x2d, 0x20, 0x17, 0x3d,
  0x20, 0x32, 0x27, 0x20, 0x35, 0x60, 0x20, 0x44, 0x2f, 0x20, 0x74, 0x34,
  0x20, 0x75, 0x35, 0x20, 0x76, 0x36, 0x20, 0x77, 0x37, 0x20, 0x78, 0x38,
  0x20, 0x7f, 0x6e, 0x20, 0x80, 0x30, 0x20, 0x81, 0x31, 0x20, 0x82, 0x32,
  0x20, 0x83, 0x33, 0x20, 0x84, 0x34, 0x20, 0x85, 0x35, 0x20, 0x86, 0x36,
  0x20, 0x87, 0x37, 0x20, 0x88, 0x38, 0x20, 0x89, 0x39, 0x20, 0xa7, 0x50,
  0x21, 0x02, 0x43, 0x21, 0x07, 0x45, 0x21, 0x0a, 0x67, 0x21, 0x0b, 0x48,
  0x21, 0x0c, 0x48, 0x21, 0x0d, 0x48, 0x21, 0x0e, 0x68, 0x21, 0x10, 0x49,
  0x21, 0x11, 0x49, 0x21, 0x12, 0x4c, 0x21, 0x13, 0x6c, 0x21, 0x15, 0x4e,
  0x21, 0x18, 0x50, 0x21, 0x19, 0x50, 0x21, 0x1a, 0x51, 0x21, 0x1b, 0x52,
  0x21, 0x1c, 0x52, 0x21, 0x1d, 0x52, 0x21, 0x24, 0x5a, 0x21, 0x28, 0x5a,
  0x21, 0x2a, 0x4b, 0x21, 0x2c, 0x42, 0x21, 0x2d, 0x43, 0x21, 0x2e, 0x65,
  0x21, 0x2f, 0x65, 0x21, 0x30, 0x45, 0x21, 0x31, 0x46, 0x21, 0x33, 0x4d,
  0x21, 0x34, 0x6f, 0x22, 0x12, 0x2d, 0x22, 0x15, 0x2f, 0x22, 0x16, 0x5c,
  0x22, 0x17, 0x2a, 0x22, 0x1a, 0x76, 0x22, 0x1e, 0x38, 0x22, 0x23, 0x7c,
  0x22, 0x29, 0x6e, 0x22, 0x36, 0x3a, 0x22, 0x3c, 0x7e, 0x22, 0x61, 0x3d,
  0x22, 0x64, 0x3d, 0x22, 0x65, 0x3d, 0x23, 0x03, 0x5e, 0x23, 0x20, 0x28,
  0x23, 0x21, 0x29, 0x23, 0x29, 0x3c, 0x23, 0x2a, 0x3e, 0x25, 0x00, 0x2d,
  0x25, 0x0c, 0x2b, 0x25, 0x10, 0x2b, 0x25, 0x14, 0x2b, 0x25, 0x18, 0x2b,
  0x25, 0x1c, 0x2b, 0x25, 0x2c, 0x2d, 0x25, 0x34, 0x2d, 0x25, 0x3c, 0x2b,
  0x25, 0x50, 0x2d, 0x25, 0x52, 0x2b, 0x25, 0x53, 0x2b, 0x25, 0x54, 0x2b,
  0x25, 0x55, 0x2b, 0x25, 0x56, 0x2b, 0x25, 0x57, 0x2b, 0x25, 0x58, 0x2b,
  0x25, 0x59, 0x2b, 0x25, 0x5a, 0x2b, 0x25, 0x5b, 0x2b, 0x25, 0x5c, 0x2b,
  0x25, 0x5d, 0x2b, 0x25, 0x64, 0x2d, 0x25, 0x65, 0x2d, 0x25, 0x66, 0x2d,
  0x25, 0x67, 0x2d, 0x25, 0x68, 0x2d, 0x25, 0x69, 0x2d, 0x25, 0x6a, 0x2b,
  0x25, 0x6b, 0x2b, 0x25, 0x6c, 0x2b, 0x25, 0x84, 0x5f, 0x27, 0x58, 0x7c,
  0x30, 0x00, 0x20, 0x30, 0x08, 0x3c, 0x30, 0x09, 0x3e, 0x30, 0x1a, 0x5b,
  0x30, 0x1b, 0x5d, 0xff, 0x01, 0x21, 0xff, 0x02, 0x22, 0xff, 0x03, 0x23,
  0xff, 0x04, 0x24, 0xff, 0x05, 0x25, 0xff, 0x06, 0x26, 0xff, 0x07, 0x27,
  0xff, 0x08, 0x28, 0xff, 0x09, 0x29, 0xff, 0x0a, 0x2a, 0xff, 0x0b, 0x2b,
  0xff, 0x0c, 0x2c, 0xff, 0x0d, 0x2d, 0xff, 0x0e, 0x2e, 0xff, 0x0f, 0x2f,
  0xff, 0x10, 0x30, 0xff, 0x11, 0x31, 0xff, 0x12, 0x32, 0xff, 0x13, 0x33,
  0xff, 0x14, 0x34, 0xff, 0x15, 0x35, 0xff, 0x16, 0x36, 0xff, 0x17, 0x37,
  0xff, 0x18, 0x38, 0xff, 0x19, 0x39, 0xff, 0x1a, 0x3a, 0xff, 0x1b, 0x3b,
  0xff, 0x1c, 0x3c, 0xff, 0x1d, 0x3d, 0xff, 0x1e, 0x3e, 0xff, 0x20, 0x40,
  0xff, 0x21, 0x41, 0xff, 0x22, 0x42, 0xff, 0x23, 0x43, 0xff, 0x24, 0x44,
  0xff, 0x25, 0x45, 0xff, 0x26, 0x46, 0xff, 0x27, 0x47, 0xff, 0x28, 0x48,
  0xff, 0x29, 0x49, 0xff, 0x2a, 0x4a, 0xff, 0x2b, 0x4b, 0xff, 0x2c, 0x4c,
  0xff, 0x2d, 0x4d, 0xff, 0x2e, 0x4e, 0xff, 0x2f, 0x4f, 0xff, 0x30, 0x50,
  0xff, 0x31, 0x51, 0xff, 0x32, 0x52, 0xff, 0x33, 0x53, 0xff, 0x34, 0x54,
  0xff, 0x35, 0x55, 0xff, 0x36, 0x56, 0xff, 0x37, 0x57, 0xff, 0x38, 0x58,
  0xff, 0x39, 0x59, 0xff, 0x3a, 0x5a, 0xff, 0x3b, 0x5b, 0xff, 0x3c, 0x5c,
  0xff, 0x3d, 0x5d, 0xff, 0x3e, 0x5e, 0xff, 0x3f, 0x5f, 0xff, 0x40, 0x60,
  0xff, 0x41, 0x61, 0xff, 0x42, 0x62, 0xff, 0x43, 0x63, 0xff, 0x44, 0x64,
  0xff, 0x45, 0x65, 0xff, 0x46, 0x66, 0xff, 0x47, 0x67, 0xff, 0x48, 0x68,
  0xff, 0x49, 0x69, 0xff, 0x4a, 0x6a, 0xff, 0x4b, 0x6b, 0xff, 0x4c, 0x6c,
  0xff, 0x4d, 0x6d, 0xff, 0x4e, 0x6e, 0xff, 0x4f, 0x6f, 0xff, 0x50, 0x70,
  0xff, 0x51, 0x71, 0xff, 0x52, 0x72, 0xff, 0x53, 0x73, 0xff, 0x54, 0x74,
  0xff, 0x55, 0x75, 0xff, 0x56, 0x76, 0xff, 0x57, 0x77, 0xff, 0x58, 0x78,
  0xff, 0x59, 0x79, 0xff, 0x5a, 0x7a, 0xff, 0x5b, 0x7b, 0xff, 0x5c, 0x7c,
  0xff, 0x5d, 0x7d, 0xff, 0x5e, 0x7e, 0x00, 0x00, 0x00
};

/**
 * Creates a new configuration structure. Configuration structures created at
 * configuration time must not be changed afterwards in order to support lock-less
 * copying.
 *
 * @return New configuration structure.
 */
htp_cfg_t *htp_config_create() {
    htp_cfg_t *cfg = calloc(1, sizeof(htp_cfg_t));
    if (cfg == NULL) return NULL;

    cfg->field_limit_hard = HTP_HEADER_LIMIT_HARD;
    cfg->field_limit_soft = HTP_HEADER_LIMIT_SOFT;
    cfg->log_level = HTP_LOG_NOTICE;

    cfg->path_u_bestfit_map = bestfit_1252;
    cfg->path_replacement_char = '?';

    // No need to create hooks here; they will be created on-demand,
    // during callback registration

    // Set the default personality before we return
    htp_config_set_server_personality(cfg, HTP_SERVER_MINIMAL);

    return cfg;
}

/**
 * Creates a copy of the supplied configuration structure. The idea is to create
 * one or more configuration objects at configuration-time, but to use this
 * function to create per-connection copies. That way it will be possible to
 * adjust per-connection configuration as necessary, without affecting the
 * global configuration. Make sure no other thread changes the configuration
 * object while this function is operating.
 *
 * @param cfg
 * @return A copy of the configuration structure.
 */
htp_cfg_t *htp_config_copy(htp_cfg_t *cfg) {
    htp_cfg_t *copy = malloc(sizeof(htp_cfg_t));
    if (copy == NULL) return NULL;

    *copy = *cfg;

    // Create copies of the hooks' structures
    if (cfg->hook_transaction_start != NULL) {
        copy->hook_transaction_start = hook_copy(cfg->hook_transaction_start);
        if (copy->hook_transaction_start == NULL) {
            free(copy);
            return NULL;
        }
    }

    if (cfg->hook_request_line != NULL) {
        copy->hook_request_line = hook_copy(cfg->hook_request_line);
        if (copy->hook_request_line == NULL) {
            free(copy);
            return NULL;
        }
    }

    if (cfg->hook_request_uri_normalize != NULL) {
        copy->hook_request_uri_normalize = hook_copy(cfg->hook_request_uri_normalize);
        if (copy->hook_request_uri_normalize == NULL) {
            free(copy);
            return NULL;
        }
    }

    if (cfg->hook_request_headers != NULL) {
        copy->hook_request_headers = hook_copy(cfg->hook_request_headers);
        if (copy->hook_request_headers == NULL) {
            free(copy);
            return NULL;
        }
    }

    if (cfg->hook_request_body_data != NULL) {
        copy->hook_request_body_data = hook_copy(cfg->hook_request_body_data);
        if (copy->hook_request_body_data == NULL) {
            free(copy);
            return NULL;
        }
    }

    if (cfg->hook_request_trailer != NULL) {
        copy->hook_request_trailer = hook_copy(cfg->hook_request_trailer);
        if (copy->hook_request_trailer == NULL) {
            free(copy);
            return NULL;
        }
    }

    if (cfg->hook_request != NULL) {
        copy->hook_request = hook_copy(cfg->hook_request);
        if (copy->hook_request == NULL) {
            free(copy);
            return NULL;
        }
    }
    
    if (cfg->hook_response_line != NULL) {
        copy->hook_response_line = hook_copy(cfg->hook_response_line);
        if (copy->hook_response_line == NULL) {
            free(copy);
            return NULL;
        }
    }

    if (cfg->hook_response_headers != NULL) {
        copy->hook_response_headers = hook_copy(cfg->hook_response_headers);
        if (copy->hook_response_headers == NULL) {
            free(copy);
            return NULL;
        }
    }

    if (cfg->hook_response_body_data != NULL) {
        copy->hook_response_body_data = hook_copy(cfg->hook_response_body_data);
        if (copy->hook_response_body_data == NULL) {
            free(copy);
            return NULL;
        }
    }

    if (cfg->hook_response_trailer != NULL) {
        copy->hook_response_trailer = hook_copy(cfg->hook_response_trailer);
        if (copy->hook_response_trailer == NULL) {
            free(copy);
            return NULL;
        }
    }

    if (cfg->hook_response != NULL) {
        copy->hook_response = hook_copy(cfg->hook_response);
        if (copy->hook_response == NULL) {
            free(copy);
            return NULL;
        }
    }

    if (cfg->hook_log != NULL) {
        copy->hook_log = hook_copy(cfg->hook_log);
        if (copy->hook_log == NULL) {
            free(copy);
            return NULL;
        }
    }

    return copy;
}

/**
 * Destroy a configuration structure.
 * 
 * @param cfg
 */
void htp_config_destroy(htp_cfg_t *cfg) {
    // Destroy the hooks
    hook_destroy(cfg->hook_transaction_start);
    hook_destroy(cfg->hook_request_line);
    hook_destroy(cfg->hook_request_uri_normalize);
    hook_destroy(cfg->hook_request_headers);
    hook_destroy(cfg->hook_request_body_data);
    hook_destroy(cfg->hook_request_trailer);
    hook_destroy(cfg->hook_request);
    hook_destroy(cfg->hook_response_line);
    hook_destroy(cfg->hook_response_headers);
    hook_destroy(cfg->hook_response_body_data);
    hook_destroy(cfg->hook_response_trailer);
    hook_destroy(cfg->hook_response);
    hook_destroy(cfg->hook_log);

    // Free the structure itself
    free(cfg);
}

/**
 * Registers a transaction_start callback.
 * 
 * @param cfg
 * @param callback_fn 
 */
void htp_config_register_transaction_start(htp_cfg_t *cfg, int (*callback_fn)(htp_connp_t *)) {
    hook_register(&cfg->hook_transaction_start, callback_fn);
}

/**
 * Registers a request_line callback.
 *
 * @param cfg
 * @param callback_fn 
 */
void htp_config_register_request_line(htp_cfg_t *cfg, int (*callback_fn)(htp_connp_t *)) {
    hook_register(&cfg->hook_request_line, callback_fn);
}

/**
 * Registers a request_uri_normalize callback.
 *
 * @param cfg
 * @param callback_fn 
 */
void htp_config_register_request_uri_normalize(htp_cfg_t *cfg, int (*callback_fn)(htp_connp_t *)) {
    hook_register(&cfg->hook_request_uri_normalize, callback_fn);
}

/**
 * Registers a request_headers callback.
 *
 * @param cfg
 * @param callback_fn 
 */
void htp_config_register_request_headers(htp_cfg_t *cfg, int (*callback_fn)(htp_connp_t *)) {
    hook_register(&cfg->hook_request_headers, callback_fn);
}

/**
 * Registers a request_trailer callback.
 *
 * @param cfg
 * @param callback_fn 
 */
void htp_config_register_request_trailer(htp_cfg_t *cfg, int (*callback_fn)(htp_connp_t *)) {
    hook_register(&cfg->hook_request_trailer, callback_fn);
}

/**
 * Registers a request_body_data callback.
 *
 * @param cfg
 * @param callback_fn 
 */
void htp_config_register_request_body_data(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_data_t *)) {
    hook_register(&cfg->hook_request_body_data, callback_fn);
}

/**
 * Registers a request callback.
 *
 * @param cfg
 * @param callback_fn 
 */
void htp_config_register_request(htp_cfg_t *cfg, int (*callback_fn)(htp_connp_t *)) {
    hook_register(&cfg->hook_request, callback_fn);
}

/**
 * Registers a request_line callback.
 *
 * @param cfg
 * @param callback_fn 
 */
void htp_config_register_response_line(htp_cfg_t *cfg, int (*callback_fn)(htp_connp_t *)) {
    hook_register(&cfg->hook_response_line, callback_fn);
}

/**
 * Registers a request_headers callback.
 *
 * @param cfg
 * @param callback_fn 
 */
void htp_config_register_response_headers(htp_cfg_t *cfg, int (*callback_fn)(htp_connp_t *)) {
    hook_register(&cfg->hook_response_headers, callback_fn);
}

/**
 * Registers a request_trailer callback.
 *
 * @param cfg
 * @param callback_fn 
 */
void htp_config_register_response_trailer(htp_cfg_t *cfg, int (*callback_fn)(htp_connp_t *)) {
    hook_register(&cfg->hook_response_trailer, callback_fn);
}

/**
 * Registers a request_body_data callback.
 *
 * @param cfg
 * @param callback_fn 
 */
void htp_config_register_response_body_data(htp_cfg_t *cfg, int (*callback_fn)(htp_tx_data_t *)) {
    hook_register(&cfg->hook_response_body_data, callback_fn);
}

/**
 * Registers a request callback.
 *
 * @param cfg
 * @param callback_fn 
 */
void htp_config_register_response(htp_cfg_t *cfg, int (*callback_fn)(htp_connp_t *)) {
    hook_register(&cfg->hook_response, callback_fn);
}

/**
 * Registers a callback that is invoked every time there is a log message.
 *
 * @param cfg
 * @param callback_fn
 */
void htp_config_register_log(htp_cfg_t *cfg, int (*callback_fn)(htp_log_t *)) {
    hook_register(&cfg->hook_log, callback_fn);
}

/**
 * Update the best-fit map, which is used to convert UCS-2 characters into
 * single-byte characters. By default a Windows 1252 best-fit map is used. The map
 * is an list of triplets, the first 2 bytes being an UCS-2 character to map from,
 * and the third byte being the single byte to map to. Make sure that your map contains
 * the mappings to cover the fullwidth form characters (U+FF00-FFEF).
 *
 * @param cfg
 * @param map
 */
void htp_config_set_bestfit_map(htp_cfg_t *cfg, unsigned char *map) {
    cfg->path_u_bestfit_map = map;
}

/**
 * Whether to generate the request_uri_normalized field.
 *
 * @param cfg
 * @param generate
 */
void htp_config_set_generate_request_uri_normalized(htp_cfg_t *cfg, int generate) {
    cfg->generate_request_uri_normalized = generate;
}

/**
 * Configures whether backslash characters are treated as path segment separators. They
 * are not on Unix systems, but are on Windows systems. If this setting is enabled, a path
 * such as "/one\two/three" will be converted to "/one/two/three".
 *
 * @param cfg
 * @param backslash_separators
 */
void htp_config_set_path_backslash_separators(htp_cfg_t *cfg, int backslash_separators) {
    cfg->path_backslash_separators = backslash_separators;
}

/**
 * Configures whether backslash characters are treated as query segment separators. They
 * are not on Unix systems, but are on Windows systems. If this setting is enabled, a query
 * such as "/one\two/three" will be converted to "/one/two/three".
 *
 * @param cfg
 * @param backslash_separators
 */
void htp_config_set_query_backslash_separators(htp_cfg_t *cfg, int backslash_separators) {
    cfg->query_backslash_separators = backslash_separators;
}

/**
 * Configures filesystem sensitivity. This setting affects
 * how URL paths are normalized. There are no path modifications by default, but
 * on a case-insensitive systems path will be converted to lowercase.
 *
 * @param cfg
 * @param case_insensitive
 */
void htp_config_set_path_case_insensitive(htp_cfg_t *cfg, int case_insensitive) {
    cfg->path_case_insensitive = case_insensitive;
}

/**
 * Configures filesystem sensitivity. This setting affects
 * how URL querys are normalized. There are no query modifications by default, but
 * on a case-insensitive systems query will be converted to lowercase.
 *
 * @param cfg
 * @param case_insensitive
 */
void htp_config_set_query_case_insensitive(htp_cfg_t *cfg, int case_insensitive) {
    cfg->query_case_insensitive = case_insensitive;
}

/**
 * Configures whether consecutive path segment separators will be compressed. When
 * enabled, a path such as "/one//two" will be normalized to "/one/two". The backslash_separators
 * and decode_separators parameters are used before compression takes place. For example, if
 * backshasl_deparators and decode_separators are both enabled, the path "/one\\/two\/%5cthree/%2f//four"
 * will be converted to "/one/two/three/four".
 *
 * @param cfg
 * @param compress_separators
 */
void htp_config_set_path_compress_separators(htp_cfg_t *cfg, int compress_separators) {
    cfg->path_compress_separators = compress_separators;
}

/**
 * Configures whether consecutive query segment separators will be compressed. When
 * enabled, a query such as "/one//two" will be normalized to "/one/two". The backslash_separators
 * and decode_separators parameters are used before compression takes place. For example, if
 * backshasl_deparators and decode_separators are both enabled, the query "/one\\/two\/%5cthree/%2f//four"
 * will be converted to "/one/two/three/four".
 *
 * @param cfg
 * @param compress_separators
 */
void htp_config_set_query_compress_separators(htp_cfg_t *cfg, int compress_separators) {
    cfg->query_compress_separators = compress_separators;
}

/**
 * This parameter is used to predict how a server will react when control
 * characters are present in a request path, but does not affect path
 * normalization.
 *
 * @param cfg
 * @param control_char_handling Use NONE with servers that ignore control characters in
 *                              request path, and STATUS_400 with servers that respond
 *                              with 400.
 */
void htp_config_set_path_control_char_handling(htp_cfg_t *cfg, int control_char_handling) {
    cfg->path_control_char_handling = control_char_handling;
}

/**
 * This parameter is used to predict how a server will react when control
 * characters are present in a request query, but does not affect query
 * normalization.
 *
 * @param cfg
 * @param control_char_handling Use NONE with servers that ignore control characters in
 *                              request query, and STATUS_400 with servers that respond
 *                              with 400.
 */
void htp_config_set_query_control_char_handling(htp_cfg_t *cfg, int control_char_handling) {
    cfg->query_control_char_handling = control_char_handling;
}

/**
 * Controls the UTF-8 treatment of request paths. One option is to only validate
 * path as UTF-8. In this case, the UTF-8 flags will be raised as appropriate, and
 * the path will remain in UTF-8 (if it was UTF-8in the first place). The other option
 * is to convert a UTF-8 path into a single byte stream using best-fit mapping.
 *
 * @param cfg
 * @param convert_utf8
 */
void htp_config_set_path_convert_utf8(htp_cfg_t *cfg, int convert_utf8) {
    cfg->path_convert_utf8 = convert_utf8;
}

/**
 * Configures whether encoded path segment separators will be decoded. Apache does
 * not do this, but IIS does. If enabled, a path such as "/one%2ftwo" will be normalized
 * to "/one/two". If the backslash_separators option is also enabled, encoded backslash
 * characters will be converted too (and subseqently normalized to forward slashes).
 *
 * @param cfg
 * @param decode_separators
 */
void htp_config_set_path_decode_separators(htp_cfg_t *cfg, int decode_separators) {
    cfg->path_decode_separators = decode_separators;
}

/**
 * Configures whether encoded query segment separators will be decoded. Apache does
 * not do this, but IIS does. If enabled, a query such as "/one%2ftwo" will be normalized
 * to "/one/two". If the backslash_separators option is also enabled, encoded backslash
 * characters will be converted too (and subseqently normalized to forward slashes).
 *
 * @param cfg
 * @param decode_separators
 */
void htp_config_set_query_decode_separators(htp_cfg_t *cfg, int decode_separators) {
    cfg->query_decode_separators = decode_separators;
}

/**
 * Configures whether %u-encoded sequences in path will be decoded. Such sequences
 * will be treated as invalid URL encoding if decoding is not desireable. 
 *
 * @param cfg
 * @param decode_u_encoding
 */
void htp_config_set_path_decode_u_encoding(htp_cfg_t *cfg, int decode_u_encoding) {
    cfg->path_decode_u_encoding = decode_u_encoding;
}

/**
 * Configures whether %u-encoded sequences in query will be decoded. Such sequences
 * will be treated as invalid URL encoding if decoding is not desireable.
 *
 * @param cfg
 * @param decode_u_encoding
 */
void htp_config_set_query_decode_u_encoding(htp_cfg_t *cfg, int decode_u_encoding) {
    cfg->query_decode_u_encoding = decode_u_encoding;
}

/**
 * Configures how server reacts to invalid encoding in path.
 *
 * @param cfg
 * @param invalid_encoding_handling The available options are: URL_DECODER_PRESERVE_PERCENT,
 *                                  URL_DECODER_REMOVE_PERCENT, URL_DECODER_DECODE_INVALID
 *                                  and URL_DECODER_STATUS_400.
 */
void htp_config_set_path_invalid_encoding_handling(htp_cfg_t *cfg, int invalid_encoding_handling) {
    cfg->path_invalid_encoding_handling = invalid_encoding_handling;
}

/**
 * Configures how server reacts to invalid encoding in query.
 *
 * @param cfg
 * @param invalid_encoding_handling The available options are: URL_DECODER_PRESERVE_PERCENT,
 *                                  URL_DECODER_REMOVE_PERCENT, URL_DECODER_DECODE_INVALID
 *                                  and URL_DECODER_STATUS_400.
 */
void htp_config_set_query_invalid_encoding_handling(htp_cfg_t *cfg, int invalid_encoding_handling) {
    cfg->query_invalid_encoding_handling = invalid_encoding_handling;
}


/**
 * Configures how server reacts to invalid UTF-8 characters in path. This setting will
 * not affect path normalization; it only controls what response status we expect for
 * a request that contains invalid UTF-8 characters.
 *
 * @param cfg
 * @param invalid_utf8_handling Possible values: NONE or STATUS_400.
 */
void htp_config_set_path_invalid_utf8_handling(htp_cfg_t *cfg, int invalid_utf8_handling) {
    cfg->path_invalid_utf8_handling = invalid_utf8_handling;
}

/**
 * Configures how server reacts to encoded NUL bytes. Some servers will terminate
 * path at NUL, while some will respond with 400 or 404. When the termination option
 * is not used, the NUL byte will remain in the path.
 *
 * @param cfg
 * @param nul_encoded_handling Possible values: TERMINATE, STATUS_400, STATUS_404
 */
void htp_config_set_path_nul_encoded_handling(htp_cfg_t *cfg, int nul_encoded_handling) {
    cfg->path_nul_encoded_handling = nul_encoded_handling;
}

/**
 * Configures how server reacts to encoded NUL bytes. Some servers will terminate
 * query at NUL, while some will respond with 400 or 404. When the termination option
 * is not used, the NUL byte will remain in the query.
 *
 * @param cfg
 * @param nul_encoded_handling Possible values: TERMINATE, STATUS_400, STATUS_404
 */
void htp_config_set_query_nul_encoded_handling(htp_cfg_t *cfg, int nul_encoded_handling) {
    cfg->query_nul_encoded_handling = nul_encoded_handling;
}

/**
 * Configures how server reacts to raw NUL bytes. Some servers will terminate
 * path at NUL, while some will respond with 400 or 404. When the termination option
 * is not used, the NUL byte will remain in the path.
 *
 * @param cfg
 * @param nul_raw_handling Possible values: TERMINATE, STATUS_400, STATUS_404
 */
void htp_config_set_path_nul_raw_handling(htp_cfg_t *cfg, int nul_raw_handling) {
    cfg->path_nul_raw_handling = nul_raw_handling;
}

/**
 * Configures how server reacts to raw NUL bytes. Some servers will terminate
 * query at NUL, while some will respond with 400 or 404. When the termination option
 * is not used, the NUL byte will remain in the query.
 *
 * @param cfg
 * @param nul_raw_handling Possible values: TERMINATE, STATUS_400, STATUS_404
 */
void htp_config_set_query_nul_raw_handling(htp_cfg_t *cfg, int nul_raw_handling) {
    cfg->query_nul_raw_handling = nul_raw_handling;
}

/**
 * Sets the replacement characater that will be used to in the lossy best-fit
 * mapping from Unicode characters into single-byte streams. The question mark
 * is the default replacement character.
 *
 * @param cfg
 * @param replacement_char
 */
void htp_config_set_path_replacement_char(htp_cfg_t *cfg, int replacement_char) {
    cfg->path_replacement_char = replacement_char;
}

/**
 * Controls what the library does when it encounters an Unicode character where
 * only a single-byte would do (e.g., the %u-encoded characters). Conversion always
 * takes place; this parameter is used to correctly predict the status code used
 * in response. In the future there will probably be an option to convert such
 * characters to UCS-2 or UTF-8.
 *
 * @param cfg
 * @param unicode_mapping Possible values: BESTFIT, STATUS_400, STATUS_404.
 */
void htp_config_set_path_unicode_mapping(htp_cfg_t *cfg, int unicode_mapping) {
    cfg->path_unicode_mapping = unicode_mapping;
}

/**
 * Controls how server reacts to overlong UTF-8 characters.
 * XXX Not used at the moment.
 *
 * @param cfg
 * @param utf8_overlong_handling
 */
void htp_config_set_path_utf8_overlong_handling(htp_cfg_t *cfg, int utf8_overlong_handling) {
    cfg->path_utf8_overlong_handling = utf8_overlong_handling;
}

/**
 * Configure desired server personality.
 *
 * @param cfg
 * @param personality
 * @return HTP_OK if the personality is supported, HTP_ERROR if it isn't.
 */
int htp_config_set_server_personality(htp_cfg_t *cfg, int personality) {
    switch (personality) {
        case HTP_SERVER_MINIMAL:
            cfg->parse_request_line = htp_parse_request_line_generic;
            cfg->process_request_header = htp_process_request_header_generic;
            cfg->parse_response_line = htp_parse_response_line_generic;
            cfg->process_response_header = htp_process_response_header_generic;
            break;

        case HTP_SERVER_GENERIC:
            cfg->parse_request_line = htp_parse_request_line_generic;
            cfg->process_request_header = htp_process_request_header_generic;
            cfg->parse_response_line = htp_parse_response_line_generic;
            cfg->process_response_header = htp_process_response_header_generic;

            cfg->path_backslash_separators = YES;
            cfg->path_decode_separators = YES;
            cfg->path_compress_separators = YES;

//            cfg->query_backslash_separators = YES;
            cfg->query_decode_separators = YES;
//            cfg->query_compress_separators = YES;
            break;

        case HTP_SERVER_IDS:
            cfg->parse_request_line = htp_parse_request_line_generic;
            cfg->process_request_header = htp_process_request_header_generic;
            cfg->parse_response_line = htp_parse_response_line_generic;
            cfg->process_response_header = htp_process_response_header_generic;

            cfg->path_backslash_separators = YES;
            cfg->path_case_insensitive = YES;
            cfg->path_decode_separators = YES;
            cfg->path_compress_separators = YES;
            cfg->path_decode_u_encoding = YES;
            cfg->path_unicode_mapping = BESTFIT;
            cfg->path_convert_utf8 = YES;

//            cfg->query_backslash_separators = YES;
            cfg->query_case_insensitive = YES;
            cfg->query_decode_separators = YES;
//            cfg->query_compress_separators = YES;
            cfg->query_decode_u_encoding = YES;
            break;

        case HTP_SERVER_APACHE :
        case HTP_SERVER_APACHE_2_2:
            cfg->parse_request_line = htp_parse_request_line_apache_2_2;
            cfg->process_request_header = htp_process_request_header_apache_2_2;
            cfg->parse_response_line = htp_parse_response_line_generic;
            cfg->process_response_header = htp_process_response_header_generic;
            
            cfg->path_backslash_separators = NO;
            cfg->path_decode_separators = NO;
            cfg->path_compress_separators = YES;
            cfg->path_invalid_encoding_handling = URL_DECODER_STATUS_400;            
            cfg->path_control_char_handling = NONE;

//            cfg->query_backslash_separators = NO;
            cfg->query_decode_separators = NO;
//            cfg->query_compress_separators = YES;
            cfg->query_invalid_encoding_handling = URL_DECODER_STATUS_400;
            cfg->query_control_char_handling = NONE;
            break;

        case HTP_SERVER_IIS_5_1:
            cfg->parse_request_line = htp_parse_request_line_generic;
            cfg->process_request_header = htp_process_request_header_generic;
            cfg->parse_response_line = htp_parse_response_line_generic;
            cfg->process_response_header = htp_process_response_header_generic;

            cfg->path_backslash_separators = YES;
            cfg->path_decode_separators = NO;
            cfg->path_compress_separators = YES;
            cfg->path_invalid_encoding_handling = URL_DECODER_PRESERVE_PERCENT;
            cfg->path_decode_u_encoding = YES;
            cfg->path_unicode_mapping = BESTFIT;
            cfg->path_control_char_handling = NONE;

//            cfg->query_backslash_separators = YES;
            cfg->query_decode_separators = NO;
//            cfg->query_compress_separators = YES;
            cfg->query_invalid_encoding_handling = URL_DECODER_PRESERVE_PERCENT;
            cfg->query_decode_u_encoding = YES;
//            cfg->query_unicode_mapping = BESTFIT;
            cfg->query_control_char_handling = NONE;
            break;

        case HTP_SERVER_IIS_6_0:
            cfg->parse_request_line = htp_parse_request_line_generic;
            cfg->process_request_header = htp_process_request_header_generic;
            cfg->parse_response_line = htp_parse_response_line_generic;
            cfg->process_response_header = htp_process_response_header_generic;

            cfg->path_backslash_separators = YES;
            cfg->path_decode_separators = YES;
            cfg->path_compress_separators = YES;
            cfg->path_invalid_encoding_handling = URL_DECODER_STATUS_400;
            cfg->path_decode_u_encoding = YES;
            cfg->path_unicode_mapping = STATUS_400;
            cfg->path_control_char_handling = STATUS_400;

//            cfg->query_backslash_separators = YES;
            cfg->query_decode_separators = YES;
//            cfg->query_compress_separators = YES;
            cfg->query_invalid_encoding_handling = URL_DECODER_STATUS_400;
            cfg->query_decode_u_encoding = YES;
//            cfg->query_unicode_mapping = STATUS_400;
            cfg->query_control_char_handling = STATUS_400;
            break;

        case HTP_SERVER_IIS_7_0:
        case HTP_SERVER_IIS_7_5:
            cfg->parse_request_line = htp_parse_request_line_generic;
            cfg->process_request_header = htp_process_request_header_generic;
            cfg->parse_response_line = htp_parse_response_line_generic;
            cfg->process_response_header = htp_process_response_header_generic;

            cfg->path_backslash_separators = YES;
            cfg->path_decode_separators = YES;
            cfg->path_compress_separators = YES;
            cfg->path_invalid_encoding_handling = URL_DECODER_STATUS_400;
            cfg->path_control_char_handling = STATUS_400;

//            cfg->query_backslash_separators = YES;
            cfg->query_decode_separators = YES;
//            cfg->query_compress_separators = YES;
            cfg->query_invalid_encoding_handling = URL_DECODER_STATUS_400;
            cfg->query_control_char_handling = STATUS_400;
            break;
            
        default:
            return HTP_ERROR;
    }

    // Remember the personality
    cfg->spersonality = personality;   

    return HTP_OK;
}
