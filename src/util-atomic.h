/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 *
 * API for atomic operations. Uses C11 atomic instructions
 * where available, GCC/clang specific (gnu99) operations otherwise.
 *
 * To prevent developers from accidentally working with the atomic variables
 * directly instead of through the proper macro's, a marco trick is performed
 * that exposes different variable names than the developer uses. So if the dev
 * uses "somevar", internally "somevar_sc_atomic__" is used.
 */


#ifndef __UTIL_ATOMIC_H__
#define __UTIL_ATOMIC_H__

#if HAVE_STDATOMIC_H==1

#include <stdatomic.h>

#define SC_ATOMIC_MEMORY_ORDER_RELAXED memory_order_relaxed
#define SC_ATOMIC_MEMORY_ORDER_CONSUME memory_order_consume
#define SC_ATOMIC_MEMORY_ORDER_ACQUIRE memory_order_acquire
#define SC_ATOMIC_MEMORY_ORDER_RELEASE memory_order_release
#define SC_ATOMIC_MEMORY_ORDER_ACQ_REL memory_order_acq_rel
#define SC_ATOMIC_MEMORY_ORDER_SEQ_CST memory_order_seq_cst

/**
 *  \brief wrapper for declaring atomic variables.
 *
 *  \param type Type of the variable (char, short, int, long, long long)
 *  \param name Name of the variable.
 *
 *  We just declare the variable here as we rely on atomic operations
 *  to modify it, so no need for locks.
 *
 *  \warning variable is not initialized
 */
#define SC_ATOMIC_DECLARE(type, name) \
    _Atomic(type) name ## _sc_atomic__

/**
 *  \brief wrapper for referencing an atomic variable declared on another file.
 *
 *  \param type Type of the variable (char, short, int, long, long long)
 *  \param name Name of the variable.
 *
 *  We just declare the variable here as we rely on atomic operations
 *  to modify it, so no need for locks.
 *
 */
#define SC_ATOMIC_EXTERN(type, name) \
    extern _Atomic(type) (name ## _sc_atomic__)

/**
 *  \brief wrapper for declaring an atomic variable and initializing it.
 **/
#define SC_ATOMIC_DECL_AND_INIT(type, name) \
    _Atomic(type) (name ## _sc_atomic__) = 0

/**
 *  \brief wrapper for declaring an atomic variable and initializing it
 *  to a specific value
 **/
#define SC_ATOMIC_DECL_AND_INIT_WITH_VAL(type, name, val) _Atomic(type)(name##_sc_atomic__) = val

/**
 *  \brief wrapper for initializing an atomic variable.
 **/
#define SC_ATOMIC_INIT(name) \
    (name ## _sc_atomic__) = 0
#define SC_ATOMIC_INITPTR(name) \
    (name ## _sc_atomic__) = NULL

/**
 *  \brief wrapper for reinitializing an atomic variable.
 **/
#define SC_ATOMIC_RESET(name) \
    SC_ATOMIC_INIT(name)

/**
 *  \brief add a value to our atomic variable
 *
 *  \param name the atomic variable
 *  \param val the value to add to the variable
 */
#define SC_ATOMIC_ADD(name, val) \
    atomic_fetch_add(&(name ## _sc_atomic__), (val))

/**
 *  \brief sub a value from our atomic variable
 *
 *  \param name the atomic variable
 *  \param val the value to sub from the variable
 */
#define SC_ATOMIC_SUB(name, val) \
    atomic_fetch_sub(&(name ## _sc_atomic__), (val))

/**
 *  \brief Bitwise OR a value to our atomic variable
 *
 *  \param name the atomic variable
 *  \param val the value to OR to the variable
 */
#define SC_ATOMIC_OR(name, val) \
    atomic_fetch_or(&(name ## _sc_atomic__), (val))

/**
 *  \brief Bitwise AND a value to our atomic variable
 *
 *  \param name the atomic variable
 *  \param val the value to AND to the variable
 */
#define SC_ATOMIC_AND(name, val) \
    atomic_fetch_and(&(name ## _sc_atomic__), (val))

/**
 *  \brief atomic Compare and Switch
 *
 *  \warning "name" is passed to us as "&var"
 */
#define SC_ATOMIC_CAS(name, cmpval, newval) \
    atomic_compare_exchange_strong((name ## _sc_atomic__), &(cmpval), (newval))

/**
 *  \brief Get the value from the atomic variable.
 *
 *  \retval var value
 */
#define SC_ATOMIC_GET(name) \
    atomic_load(&(name ## _sc_atomic__))

#define SC_ATOMIC_LOAD_EXPLICIT(name, order) \
    atomic_load_explicit(&(name ## _sc_atomic__), (order))

/**
 *  \brief Set the value for the atomic variable.
 *
 *  \retval var value
 */
#define SC_ATOMIC_SET(name, val)    \
    atomic_store(&(name ## _sc_atomic__), (val))

#else

#define SC_ATOMIC_MEMORY_ORDER_RELAXED
#define SC_ATOMIC_MEMORY_ORDER_CONSUME
#define SC_ATOMIC_MEMORY_ORDER_ACQUIRE
#define SC_ATOMIC_MEMORY_ORDER_RELEASE
#define SC_ATOMIC_MEMORY_ORDER_ACQ_REL
#define SC_ATOMIC_MEMORY_ORDER_SEQ_CST

/**
 *  \brief wrapper for OS/compiler specific atomic compare and swap (CAS)
 *         function.
 *
 *  \param addr Address of the variable to CAS
 *  \param tv Test value to compare the value at address against
 *  \param nv New value to set the variable at addr to
 *
 *  \retval 0 CAS failed
 *  \retval 1 CAS succeeded
 */
#define SCAtomicCompareAndSwap(addr, tv, nv) \
    __sync_bool_compare_and_swap((addr), (tv), (nv))

/**
 *  \brief wrapper for OS/compiler specific atomic fetch and add
 *         function.
 *
 *  \param addr Address of the variable to add to
 *  \param value Value to add to the variable at addr
 */
#define SCAtomicFetchAndAdd(addr, value) \
    __sync_fetch_and_add((addr), (value))

/**
 *  \brief wrapper for OS/compiler specific atomic fetch and sub
 *         function.
 *
 *  \param addr Address of the variable to add to
 *  \param value Value to sub from the variable at addr
 */
#define SCAtomicFetchAndSub(addr, value) \
    __sync_fetch_and_sub((addr), (value))

/**
 *  \brief wrapper for OS/compiler specific atomic fetch and add
 *         function.
 *
 *  \param addr Address of the variable to add to
 *  \param value Value to add to the variable at addr
 */
#define SCAtomicAddAndFetch(addr, value) \
    __sync_add_and_fetch((addr), (value))

/**
 *  \brief wrapper for OS/compiler specific atomic fetch and sub
 *         function.
 *
 *  \param addr Address of the variable to add to
 *  \param value Value to sub from the variable at addr
 */
#define SCAtomicSubAndFetch(addr, value) \
    __sync_sub_and_fetch((addr), (value))

/**
 *  \brief wrapper for OS/compiler specific atomic fetch and "AND"
 *         function.
 *
 *  \param addr Address of the variable to AND to
 *  \param value Value to add to the variable at addr
 */
#define SCAtomicFetchAndAnd(addr, value) \
    __sync_fetch_and_and((addr), (value))

/**
 *  \brief wrapper for OS/compiler specific atomic fetch and "NAND"
 *         function.
 *
 *  \param addr Address of the variable to NAND to
 *  \param value Value to add to the variable at addr
 */
#define SCAtomicFetchAndNand(addr, value) \
    __sync_fetch_and_nand((addr), (value))

/**
 *  \brief wrapper for OS/compiler specific atomic fetch and "XOR"
 *         function.
 *
 *  \param addr Address of the variable to XOR to
 *  \param value Value to add to the variable at addr
 */
#define SCAtomicFetchAndXor(addr, value) \
    __sync_fetch_and_xor((addr), (value))

/**
 *  \brief wrapper for OS/compiler specific atomic fetch and or
 *         function.
 *
 *  \param addr Address of the variable to or to
 *  \param value Value to add to the variable at addr
 */
#define SCAtomicFetchAndOr(addr, value) \
    __sync_fetch_and_or((addr), (value))

/**
 *  \brief wrapper for declaring atomic variables.
 *
 *  \warning Only char, short, int, long, long long and their unsigned
 *           versions are supported.
 *
 *  \param type Type of the variable (char, short, int, long, long long)
 *  \param name Name of the variable.
 *
 *  We just declare the variable here as we rely on atomic operations
 *  to modify it, so no need for locks.
 *
 *  \warning variable is not initialized
 */
#define SC_ATOMIC_DECLARE(type, name) \
    type name ## _sc_atomic__

/**
 *  \brief wrapper for referencing an atomic variable declared on another file.
 *
 *  \warning Only char, short, int, long, long long and their unsigned
 *           versions are supported.
 *
 *  \param type Type of the variable (char, short, int, long, long long)
 *  \param name Name of the variable.
 *
 *  We just declare the variable here as we rely on atomic operations
 *  to modify it, so no need for locks.
 *
 */
#define SC_ATOMIC_EXTERN(type, name) \
    extern type name ## _sc_atomic__

/**
 *  \brief wrapper for declaring an atomic variable and initializing it
 *  to a specific value
 **/
#define SC_ATOMIC_DECL_AND_INIT_WITH_VAL(type, name, val) type name##_sc_atomic__ = val

/**
 *  \brief wrapper for declaring an atomic variable and initializing it.
 **/
#define SC_ATOMIC_DECL_AND_INIT(type, name) \
    type name ## _sc_atomic__ = 0

/**
 *  \brief wrapper for initializing an atomic variable.
 **/
#define SC_ATOMIC_INIT(name) \
    (name ## _sc_atomic__) = 0

#define SC_ATOMIC_INITPTR(name) \
    (name ## _sc_atomic__) = NULL

/**
 *  \brief wrapper for reinitializing an atomic variable.
 **/
#define SC_ATOMIC_RESET(name) \
    (name ## _sc_atomic__) = 0

/**
 *  \brief add a value to our atomic variable
 *
 *  \param name the atomic variable
 *  \param val the value to add to the variable
 */
#define SC_ATOMIC_ADD(name, val) \
    SCAtomicFetchAndAdd(&(name ## _sc_atomic__), (val))

/**
 *  \brief sub a value from our atomic variable
 *
 *  \param name the atomic variable
 *  \param val the value to sub from the variable
 */
#define SC_ATOMIC_SUB(name, val) \
    SCAtomicFetchAndSub(&(name ## _sc_atomic__), (val))

/**
 *  \brief Bitwise OR a value to our atomic variable
 *
 *  \param name the atomic variable
 *  \param val the value to OR to the variable
 */
#define SC_ATOMIC_OR(name, val) \
    SCAtomicFetchAndOr(&(name ## _sc_atomic__), (val))

/**
 *  \brief Bitwise AND a value to our atomic variable
 *
 *  \param name the atomic variable
 *  \param val the value to AND to the variable
 */
#define SC_ATOMIC_AND(name, val) \
    SCAtomicFetchAndAnd(&(name ## _sc_atomic__), (val))

/**
 *  \brief atomic Compare and Switch
 *
 *  \warning "name" is passed to us as "&var"
 */
#define SC_ATOMIC_CAS(name, cmpval, newval) \
    SCAtomicCompareAndSwap((name ## _sc_atomic__), cmpval, newval)

/**
 *  \brief Get the value from the atomic variable.
 *
 *  \retval var value
 */
#define SC_ATOMIC_GET(name) \
    (name ## _sc_atomic__)

#define SC_ATOMIC_LOAD_EXPLICIT(name, order) \
    (name ## _sc_atomic__)

/**
 *  \brief Set the value for the atomic variable.
 *
 *  \retval var value
 */
#define SC_ATOMIC_SET(name, val) ({       \
    while (SC_ATOMIC_CAS(&name, SC_ATOMIC_GET(name), val) == 0) \
        ;                                                       \
        })

#endif /* no c11 atomics */

void SCAtomicRegisterTests(void);

#endif /* __UTIL_ATOMIC_H__ */

