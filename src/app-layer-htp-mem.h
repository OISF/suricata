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


void HTPParseMemcap(void);
void *HTPMalloc(size_t size);
void *HTPCalloc(size_t n, size_t size);
void *HTPRealloc(void *ptr, size_t orig_size, size_t size);
void HTPFree(void *ptr, size_t size);

int HTPSetMemcap(uint64_t size);
uint64_t HTPGetMemcap(void);

uint64_t HTPMemuseGlobalCounter(void);
uint64_t HTPMemcapGlobalCounter(void);
