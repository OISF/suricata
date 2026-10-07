/* Copyright (C) 2026 Open Information Security Foundation
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

/**
 * \file
 *
 * Definition of the configuration node, private to conf.c and the YAML
 * loader. Everything else uses the accessors in conf.h.
 */

#ifndef SURICATA_CONF_PRIVATE_H
#define SURICATA_CONF_PRIVATE_H

#include "queue.h"
#include "conf.h"

/**
 * Structure of a configuration parameter.
 */
struct SCConfNode_ {
    char *name;
    char *val;

    int is_seq;

    /**< Flag that sets this nodes value as final. */
    int final;

    struct SCConfNode_ *parent;
    TAILQ_HEAD(, SCConfNode_) head;
    TAILQ_ENTRY(SCConfNode_) next;
};

#endif /* SURICATA_CONF_PRIVATE_H */
