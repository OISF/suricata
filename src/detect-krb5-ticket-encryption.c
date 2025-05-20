/* Copyright (C) 2022 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include "suricata-common.h"
#include "rust.h"

#include "detect-krb5-ticket-encryption.h"

#include "detect-engine.h"
#include "detect-parse.h"

static int g_krb5_ticket_encryption_list_id = 0;

static void DetectKrb5TicketEncryptionFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCKrb5DetectEncryptionFree(ptr);
}

static int DetectKrb5TicketEncryptionMatch(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags,
        void *state, void *txv, const Signature *s, const SigMatchCtx *ctx)
{
    const DetectKrb5TicketEncryptionData *dd = (const DetectKrb5TicketEncryptionData *)ctx;

    SCEnter();

    SCReturnInt(SCKrb5DetectEncryptionMatch(txv, dd));
}

static int DetectKrb5TicketEncryptionSetup(
        DetectEngineCtx *de_ctx, Signature *s, const char *krb5str)
{
    DetectKrb5TicketEncryptionData *krb5d = NULL;

    if (SCDetectSignatureSetAppProto(s, ALPROTO_KRB5) != 0)
        return -1;

    krb5d = SCKrb5DetectEncryptionParse(krb5str);
    if (krb5d == NULL)
        goto error;

    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_KRB5_TICKET_ENCRYPTION, (SigMatchCtx *)krb5d,
                g_krb5_ticket_encryption_list_id) == NULL) {
        goto error;
    }

    return 0;

error:
    if (krb5d != NULL)
        DetectKrb5TicketEncryptionFree(de_ctx, krb5d);
    return -1;
}

void DetectKrb5TicketEncryptionRegister(void)
{
    sigmatch_table[DETECT_KRB5_TICKET_ENCRYPTION].name = "krb5.ticket_encryption";
    sigmatch_table[DETECT_KRB5_TICKET_ENCRYPTION].desc = "match Kerberos 5 ticket encryption";
    sigmatch_table[DETECT_KRB5_TICKET_ENCRYPTION].url =
            "/rules/kerberos-keywords.html#krb5-ticket-encryption";
    sigmatch_table[DETECT_KRB5_TICKET_ENCRYPTION].Match = NULL;
    sigmatch_table[DETECT_KRB5_TICKET_ENCRYPTION].AppLayerTxMatch = DetectKrb5TicketEncryptionMatch;
    sigmatch_table[DETECT_KRB5_TICKET_ENCRYPTION].Setup = DetectKrb5TicketEncryptionSetup;
    sigmatch_table[DETECT_KRB5_TICKET_ENCRYPTION].Free = DetectKrb5TicketEncryptionFree;

    // Tickets are only from server to client
    DetectAppLayerInspectEngineRegister("krb5_ticket_encryption", ALPROTO_KRB5, SIG_FLAG_TOCLIENT,
            0, DetectEngineInspectGenericList, NULL);

    g_krb5_ticket_encryption_list_id = DetectBufferTypeRegister("krb5_ticket_encryption");
    SCLogDebug("g_krb5_ticket_encryption_list_id %d", g_krb5_ticket_encryption_list_id);
}
