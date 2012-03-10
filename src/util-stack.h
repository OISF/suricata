/* Copyright (C) 2007-2012 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Simple low level stack implementation using atomics.
 *
 * Data types using this stack should have a ptr of their own type called:
 * stack_next.
 *
 * E.g.
 * typedef struct MyStruct_ {
 *     int abc;
 *     struct MyStruct_ *stack_next;
 * } MyStruct;
 *
 */

#ifndef __UTIL_STACK_H__
#define __UTIL_STACK_H__

#include "util-atomic.h"

typedef struct Stack_ {
    /** stack head ptr */
    SC_ATOMIC_DECLARE(void *, head);
} Stack;

/** \brief int the stack
 *
 *  \param stack the stack
 */
#define STACK_INIT(stack) ({                                                \
    SC_ATOMIC_INIT((stack)->head);                                          \
})

/** \brief destroy the stack
 *
 *  \param stack the stack
 */
#define STACK_DESTROY(stack) ({                                             \
    SC_ATOMIC_DESTROY((stack)->head);                                       \
})

/** \brief check if a stack is empty
 *
 *  \param stack the stack
 *
 *  \retval 1 empty
 *  \retval 0 not empty
 */
#define STACK_EMPTY(stack)                                                  \
    (SC_ATOMIC_GET((stack)->head) == NULL)

/** \brief pop from the stack
 *
 *  \param stack the stack
 *  \param type data type
 *
 *  \retval ptr or NULL
 */
#define STACK_POP(stack, type) ({                                           \
    struct type *ptr;                                                       \
    do {                                                                    \
        ptr = (struct type *)SC_ATOMIC_GET((stack)->head);                  \
        if (ptr == NULL) {                                                  \
            break;                                                          \
        }                                                                   \
    } while (!(SC_ATOMIC_CAS(&(stack)->head, ptr, ptr->stack_next)));       \
    ptr;                                                                    \
})

/** \brief push to the stack
 *
 *  \param stack the stack
 *  \param ptr pointer to data to push to the stack
 *  \param type data type
 */
#define STACK_PUSH(stack, ptr, type) ({                                     \
    do {                                                                    \
        (ptr)->stack_next = (struct type *)SC_ATOMIC_GET((stack)->head);    \
    } while (!(SC_ATOMIC_CAS(&(stack)->head, (ptr)->stack_next, (ptr))));   \
})

#endif /* __UTIL_STACK_H__ */

