/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * API for atomic operations. Uses atomic instructions (GCC only at this time)
 * where available, falls back to (spin)locked* operations otherwise.
 *
 * To prevent developers from accidentally working with the atomic variables
 * directly instead of through the proper macro's, a marco trick is performed
 * that exposes different variable names than the developer uses. So if the dev
 * uses "somevar", internally "somevar_sc_atomic__" is used.
 *
 * Where available, we use __sync_fetch_and_add and
 * __sync_bool_compare_and_swap. If those are unavailable, the API
 * transparently created a matching (spin)lock for each atomic variable. The
 * lock will be named "somevar_sc_lock__"
 *
 * (*) where spinlocks are unavailable, the threading api falls back to mutex
 */


#ifndef __UTIL_ATOMIC_H__
#define __UTIL_ATOMIC_H__

/* test if we have atomic operations support */
#ifndef __GCC_HAVE_SYNC_COMPARE_AND_SWAP_2

/**
 *  \brief wrapper to declare an atomic variable including a (spin) lock
 *         to protect it.
 *
 *  \warning Variable and lock are _not_ initialized.
 */
#define SC_ATOMIC_DECLARE(type, name) \
    type name ## _sc_atomic__; \
    SCSpinlock name ## _sc_lock__

/**
 *  \brief wrapper to declare an atomic variable including a (spin) lock
 *         to protect it and initialize them.
 */
#define SC_ATOMIC_DECL_AND_INIT(type, name) \
    type name ## _sc_atomic__ = 0; \
    SCSpinlock name ## _sc_lock__; \
    SCSpinInit(&(name ## _sc_lock__), 0) \
}

/**
 *  \brief Initialize the previously declared atomic variable and it's
 *         lock.
 */
#define SC_ATOMIC_INIT(name) do { \
        SCSpinInit(&(name ## _sc_lock__), 0); \
        (name ## _sc_atomic__) = 0; \
    } while(0)

/**
 *  \brief Initialize the previously declared atomic variable and it's
 *         lock.
 */
#define SC_ATOMIC_RESET(name) do { \
        (name ## _sc_atomic__) = 0; \
    } while(0)

/**
 *  \brief Destroy the lock used to protect this variable
 */
#define SC_ATOMIC_DESTROY(name) do { \
        SCSpinDestroy(&(name ## _sc_lock__)); \
    } while (0)

/**
 *  \brief add a value to our atomic variable
 *
 *  \param name the atomic variable
 *  \param val the value to add to the variable
 */
#define SC_ATOMIC_ADD(name, val) \
    do { \
        SCSpinLock(&(name ## _sc_lock__)); \
        (name ## _sc_atomic__) += (val); \
        SCSpinUnlock(&(name ## _sc_lock__)); \
    } while(0)

/**
 *  \brief sub a value from our atomic variable
 *
 *  \param name the atomic variable
 *  \param val the value to sub from the variable
 */
#define SC_ATOMIC_SUB(name, val) \
    do { \
        SCSpinLock(&(name ## _sc_lock__)); \
        (name ## _sc_atomic__) -= (val); \
        SCSpinUnlock(&(name ## _sc_lock__)); \
    } while(0)

/**
 *  \brief Get the value from the atomic variable.
 *
 *  \retval var value
 */
#define SC_ATOMIC_GET(name) ({ \
    typeof(name ## _sc_atomic__) var; \
    do { \
        SCSpinLock(&(name ## _sc_lock__)); \
        var = (name ## _sc_atomic__); \
        SCSpinUnlock(&(name ## _sc_lock__)); \
    } while (0); \
    var; \
})

/**
 *  \brief atomic Compare and Switch
 *
 *  \warning "name" is passed to us as "&var"
 */
#define SC_ATOMIC_CAS(name, cmpval, newval) ({ \
    char r = 0; \
    do { \
        SCSpinLock((name ## _sc_lock__)); \
        if (*(name ## _sc_atomic__) == (cmpval)) { \
            *(name ## _sc_atomic__) = (newval); \
            r = 1; \
        } \
        SCSpinUnlock((name ## _sc_lock__)); \
    } while(0); \
    r; \
})

#else /* we do have support for CAS */

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
 *  \brief wrapper for declaring an atomic variable and initializing it.
 **/
#define SC_ATOMIC_DECL_AND_INIT(type, name) \
    type name ## _sc_atomic__ = 0

/**
 *  \brief wrapper for initializing an atomic variable.
 **/
#define SC_ATOMIC_INIT(name) \
    (name ## _sc_atomic__) = 0

/**
 *  \brief wrapper for reinitializing an atomic variable.
 **/
#define SC_ATOMIC_RESET(name) \
    (name ## _sc_atomic__) = 0

/**
 *  \brief No-op.
 */
#define SC_ATOMIC_DESTROY(name)

/**
 *  \brief add a value to our atomic variable
 *
 *  \param name the atomic variable
 *  \param val the value to add to the variable
 */
#define SC_ATOMIC_ADD(name, val) \
    SCAtomicFetchAndAdd(&(name ## _sc_atomic__), (val));

/**
 *  \brief sub a value from our atomic variable
 *
 *  \param name the atomic variable
 *  \param val the value to sub from the variable
 */
#define SC_ATOMIC_SUB(name, val) \
    SCAtomicFetchAndSub(&(name ## _sc_atomic__), (val));

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

#endif /* !no atomic operations */
#endif /* __UTIL_ATOMIC_H__ */

