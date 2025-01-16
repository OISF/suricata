/*
 * We are using this file to hold APIs copied from libhtp 0.5.x.
 */

/***************************************************************************
 * Copyright (c) 2009-2010 Open Information Security Foundation
 * Copyright (c) 2010-2013 Qualys, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * - Neither the name of the Qualys, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ***************************************************************************/

/**
 * \file
 *
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * APIs from libhtp 0.5.x.
 */

#ifndef SURICATA_APP_LAYER_HTP_LIBHTP__H
#define SURICATA_APP_LAYER_HTP_LIBHTP__H

#include "suricata-common.h"

// Temporary alias definitions before switching to libhtp rust
#define HTP_STATUS_OK    HTP_OK
#define HTP_STATUS_ERROR HTP_ERROR

#define HTP_SERVER_PERSONALITY_APACHE_2 HTP_SERVER_APACHE_2
#define HTP_SERVER_PERSONALITY_MINIMAL  HTP_SERVER_MINIMAL
#define HTP_SERVER_PERSONALITY_GENERIC  HTP_SERVER_GENERIC
#define HTP_SERVER_PERSONALITY_IDS      HTP_SERVER_IDS
#define HTP_SERVER_PERSONALITY_IIS_4_0  HTP_SERVER_IIS_4_0
#define HTP_SERVER_PERSONALITY_IIS_5_0  HTP_SERVER_IIS_5_0
#define HTP_SERVER_PERSONALITY_IIS_5_1  HTP_SERVER_IIS_5_1
#define HTP_SERVER_PERSONALITY_IIS_6_0  HTP_SERVER_IIS_6_0
#define HTP_SERVER_PERSONALITY_IIS_7_0  HTP_SERVER_IIS_7_0
#define HTP_SERVER_PERSONALITY_IIS_7_5  HTP_SERVER_IIS_7_5

#define HTP_FLAGS_REQUEST_INVALID_T_E HTP_REQUEST_INVALID_T_E
#define HTP_FLAGS_REQUEST_INVALID_C_L HTP_REQUEST_INVALID_C_L
#define HTP_FLAGS_HOST_MISSING        HTP_HOST_MISSING
#define HTP_FLAGS_HOST_AMBIGUOUS      HTP_HOST_AMBIGUOUS
#define HTP_FLAGS_HOSTU_INVALID       HTP_HOSTU_INVALID
#define HTP_FLAGS_HOSTH_INVALID       HTP_HOSTH_INVALID

bstr *SCHTPGenerateNormalizedUri(htp_tx_t *tx, htp_uri_t *uri, bool uri_include_all);

#endif /* SURICATA_APP_LAYER_HTP_LIBHTP__H */
