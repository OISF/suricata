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

#ifndef SURICATA_UTIL_RUNNING_MODES_H
#define SURICATA_UTIL_RUNNING_MODES_H

int ListKeywords(const char *keyword_info);
int ListAppLayerProtocols(const char *conf_filename, const char *const *override_paths,
        const char *const *override_values);
int ListRuleProtocols(const char *conf_filename, const char *const *override_paths,
        const char *const *override_values);
int ListAppLayerHooks(const char *conf_filename, const char *const *override_paths,
        const char *const *override_values);
int ListAppLayerFrames(const char *conf_filename, const char *const *override_paths,
        const char *const *override_values);

#endif /* SURICATA_UTIL_RUNNING_MODES_H */
