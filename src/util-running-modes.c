/* Copyright (C) 2013 Open Information Security Foundation
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

/** \file
 *
 *  \author Eric Leblond <eric@regit.org>
 */

#include "suricata-common.h"
#include "app-layer-detect-proto.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "conf-yaml-loader.h"
#include "util-running-modes.h"

int ListKeywords(const char *keyword_info)
{
    SCLogLoadConfig(0, 0, 0, 0);
    MpmTableSetup();
    SpmTableSetup();
    AppLayerSetup();
    SigTableSetup(); /* load the rule keywords */
    return SigTableList(keyword_info);
}

int ListAppLayerProtocols(const char *conf_filename)
{
    if (ConfYamlLoadFile(conf_filename) != -1)
        SCLogLoadConfig(0, 0, 0, 0);
    MpmTableSetup();
    SpmTableSetup();
    AppLayerSetup();
    AppLayerListSupportedProtocols();

    return TM_ECODE_DONE;
}

