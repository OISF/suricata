/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __UTIL_DCERPC__H__
#define __UTIL_DCERPC__H__


/*****linked list implementation*****/

typedef struct DCERPCList_ {
    void *head;
    void *tail;

    int index;
    int size;
} DCERPCList;

#define DCERPCListNext void
#define DCERPCListPrev void

typedef struct DCERPCListInterface_ {
    DCERPCListNext *next;
    DCERPCListPrev *prev;
} DCERPCListInterface;


static inline int DCERPCListIndex(DCERPCList *l)
{
    return l->index;
}

static inline int DCERPCListSize(DCERPCList *l)
{
    return l->size + l->index;
}

static inline void DCERPCListReset(DCERPCList *l, void Free(void *ptr))
{
    int i;
    DCERPCListInterface *item = l->head;
    DCERPCListInterface *next_item;
    i = 0;
    while (i < l->size) {
        next_item = item->next;
        Free(item);

        item = next_item;
        i++;
    }
    l->head = l->tail = NULL;
    l->index = l->size = 0;

    return;
}

static inline void DCERPCListAppend(void *item, DCERPCList *l)
{
    if (l->tail == NULL) {
        l->head = item;
    } else {
        ((DCERPCListInterface *)l->tail)->next = item;
        ((DCERPCListInterface *)item)->prev = l->tail;
    }
    l->tail = item;
    l->size++;

    return;
}

static inline void *DCERPCListGetAtIndex(int index, DCERPCList *l)
{
    int i;
    int idx = index - l->index;
    DCERPCListInterface *head = l->head;

    if (index < l->index || idx >= l->size)
        return NULL;

    for (i = 0; i < idx; i++)
        head = head->next;

    return head;
}

static inline void DCERPCListRemoveItem(void *item, DCERPCList *l)
{
    BUG_ON(item == NULL);
    /* the reason we have this is because for dcerpc parsers we allow
     * removing an item only if it's the head. */
    BUG_ON(item != l->head);

    DCERPCListInterface *tmp;

    if (l->head == item) {
        tmp = l->head;
        l->head = tmp->next;
    }
    if (l->tail == item) {
        tmp = l->tail;
        l->tail = tmp->prev;
    }

    tmp = item;
    if (tmp->prev != NULL)
        ((DCERPCListInterface *)tmp->prev)->next = tmp->next;
    if (tmp->next != NULL)
        ((DCERPCListInterface *)tmp->next)->prev = tmp->prev;
    l->size--;
    /* again the reason we increase the index is because this is a special
     * list, where we remove only the head element */
    l->index++;

    return;
}

#endif /* __UTIL_DCERPC__H__ */
