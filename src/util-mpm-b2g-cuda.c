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
 * \author Anoop Saldanha <poonaatsoc@gmail.com>
 */

#include "suricata-common.h"
#include "suricata.h"
#include "detect.h"
#include "detect-engine-mpm.h"
#include "util-bloomfilter.h"
#include "util-mpm-b2g-cuda.h"
#include "util-mpm.h"
#include "util-print.h"

#include "threadvars.h"
#include "tm-modules.h"

#include "util-error.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "conf.h"

#include "util-cuda-handlers.h"
#include "util-cuda.h"
#include "tm-threads.h"
#include "threads.h"
#include "tmqh-simple.h"

/* macros decides if cuda is enabled for the platform or not */
#ifdef __SC_CUDA_SUPPORT__

#define INIT_HASH_SIZE 65536

#ifdef B2G_CUDA_COUNTERS
#define COUNT(counter) (counter)
#else
#define COUNT(counter)
#endif /* B2G_CUDA_COUNTERS */

static uint32_t b2g_hash_size = 0;
static uint32_t b2g_bloom_size = 0;
static void *b2g_func;

/* threadvars Cuda(C) Mpm(M) B2G(B) Rules(R) Content(C) */
ThreadVars *tv_CMB2_RC = NULL;

/**
 * \todo Would break on x86_64 I believe.  We will fix this in a later version.
 */
#define B2G_CUDA_KERNEL_ARG0_OFFSET     0
#define B2G_CUDA_KERNEL_ARG1_OFFSET     4
#define B2G_CUDA_KERNEL_ARG2_OFFSET     8
#define B2G_CUDA_KERNEL_ARG3_OFFSET    12
#define B2G_CUDA_KERNEL_ARG4_OFFSET    16
#define B2G_CUDA_KERNEL_ARG5_OFFSET    20
#define B2G_CUDA_KERNEL_TOTAL_ARG_SIZE 24

void B2gCudaInitCtx(MpmCtx *, int);
void B2gCudaThreadInitCtx(MpmCtx *, MpmThreadCtx *, uint32_t);
void B2gCudaDestroyCtx(MpmCtx *);
void B2gCudaThreadDestroyCtx(MpmCtx *, MpmThreadCtx *);
int B2gCudaAddPatternCI(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t,
                        uint32_t, uint32_t, uint8_t);
int B2gCudaAddPatternCS(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t,
                        uint32_t, uint32_t, uint8_t);
int B2gCudaPreparePatterns(MpmCtx *mpm_ctx);
inline uint32_t B2gCudaSearchWrap(MpmCtx *, MpmThreadCtx *,
                                  PatternMatcherQueue *, uint8_t *,
                                  uint16_t);
uint32_t B2gCudaSearch1(MpmCtx *, MpmThreadCtx *, PatternMatcherQueue *,
                        uint8_t *, uint16_t);
#ifdef B2G_CUDA_SEARCH2
uint32_t B2gCudaSearch2(MpmCtx *, MpmThreadCtx *, PatternMatcherQueue *,
                        uint8_t *, uint16_t);
#endif
uint32_t B2gCudaSearch(MpmCtx *, MpmThreadCtx *, PatternMatcherQueue *,
                       uint8_t *, uint16_t);
uint32_t B2gCudaSearchBNDMq(MpmCtx *, MpmThreadCtx *, PatternMatcherQueue *,
                            uint8_t *, uint16_t);
void B2gCudaPrintInfo(MpmCtx *);
void B2gCudaPrintSearchStats(MpmThreadCtx *);
void B2gCudaRegisterTests(void);

/* for debugging purposes.  keep it for now */
int arg0 = 0;
int arg1 = 0;
int arg2 = 0;
int arg3 = 0;
int arg4 = 0;
int arg5 = 0;
int arg_total = 0;

#if defined(__x86_64__) || defined(__ia64__)
const char *b2g_cuda_ptx_image_64_bit =
    "        .version 1.4\n"
    "        .target sm_10, map_f64_to_f32\n"
    "        .entry B2gCudaSearchBNDMq (\n"
    "               .param .u64 __cudaparm_B2gCudaSearchBNDMq_offsets,\n"
    "               .param .u64 __cudaparm_B2gCudaSearchBNDMq_B2G,\n"
    "               .param .u64 __cudaparm_B2gCudaSearchBNDMq_g_u8_lowercasetable,\n"
    "               .param .u64 __cudaparm_B2gCudaSearchBNDMq_buf,\n"
    "               .param .u16 __cudaparm_B2gCudaSearchBNDMq_arg_buflen,\n"
    "               .param .u32 __cudaparm_B2gCudaSearchBNDMq_m)\n"
    "       {\n"
    "       .reg .u16 %rh<6>;\n"
    "       .reg .u32 %r<58>;\n"
    "       .reg .u64 %rd<31>;\n"
    "       .reg .pred %p<14>;\n"
    "       .loc    15      25      0\n"
    "$LBB1_B2gCudaSearchBNDMq:\n"
    "       .loc    15      27      0\n"
    "       ld.param.u32    %r1, [__cudaparm_B2gCudaSearchBNDMq_m];\n"
    "       sub.u32         %r2, %r1, 1;\n"
    "       mov.s32         %r3, %r2;\n"
    "       .loc    15      33      0\n"
    "       ld.param.u16    %r4, [__cudaparm_B2gCudaSearchBNDMq_arg_buflen];\n"
    "       shr.u32         %r5, %r4, 4;\n"
    "       cvt.u16.u32     %r6, %r5;\n"
    "       mov.s32         %r7, %r6;\n"
    "       setp.ge.u32     %p1, %r6, %r1;\n"
    "       @%p1 bra        $Lt_0_8450;\n"
    "       .loc    15      38      0\n"
    "       cvt.u16.u32     %r7, %r1;\n"
    "$Lt_0_8450:\n"
    "       cvt.u32.u16     %r8, %tid.x;\n"
    "       mul.lo.u32      %r9, %r7, %r8;\n"
    "       cvt.u16.u32     %r10, %r9;\n"
    "       add.s32         %r11, %r7, %r10;\n"
    "       setp.ge.s32     %p2, %r4, %r11;\n"
    "       @%p2 bra        $Lt_0_8962;\n"
    "       bra.uni         $LBB23_B2gCudaSearchBNDMq;\n"
    "$Lt_0_8962:\n"
    "       .loc    15      44      0\n"
    "       mul24.lo.s32    %r12, %r7, 2;\n"
    "       sub.s32         %r13, %r12, 1;\n"
    "       mov.s32         %r14, %r13;\n"
    "       cvt.u16.u32     %r15, %r14;\n"
    "       mov.s32         %r16, %r15;\n"
    "       add.s32         %r17, %r10, %r15;\n"
    "       set.lt.u32.s32  %r18, %r4, %r17;\n"
    "       neg.s32         %r19, %r18;\n"
    "       mov.u32         %r20, 15;\n"
    "       set.eq.u32.u32  %r21, %r8, %r20;\n"
    "       neg.s32         %r22, %r21;\n"
    "       or.b32  %r23, %r19, %r22;\n"
    "       mov.u32         %r24, 0;\n"
    "       setp.eq.s32     %p3, %r23, %r24;\n"
    "       @%p3 bra        $Lt_0_9474;\n"
    "       .loc    15      46      0\n"
    "       sub.u32         %r25, %r4, %r9;\n"
    "       cvt.u16.u32     %r16, %r25;\n"
    "$Lt_0_9474:\n"
    "       mov.u32         %r26, 0;\n"
    "       setp.eq.u32     %p4, %r16, %r26;\n"
    "       @%p4 bra        $Lt_0_9986;\n"
    "       mov.s32         %r27, %r16;\n"
    "       ld.param.u64    %rd1, [__cudaparm_B2gCudaSearchBNDMq_offsets];\n"
    "       mov.u32         %r28, 0;\n"
    "       mov.s32         %r29, %r27;\n"
    "$Lt_0_10498:\n"
    " //<loop> Loop body line 46, nesting depth: 1, estimated iterations: unknown\n"
    "       .loc    15      51      0\n"
    "       mov.u32         %r30, 0;\n"
    "       add.u32         %r31, %r10, %r28;\n"
    "       cvt.u64.u32     %rd2, %r31;\n"
    "       mul.lo.u64      %rd3, %rd2, 4;\n"
    "       add.u64         %rd4, %rd1, %rd3;\n"
    "       st.global.u32   [%rd4+0], %r30;\n"
    "       add.u32         %r28, %r28, 1;\n"
    "       setp.ne.u32     %p5, %r16, %r28;\n"
    "       @%p5 bra        $Lt_0_10498;\n"
    "$Lt_0_9986:\n"
    "       sub.u32         %r32, %r16, 1;\n"
    "       setp.gt.u32     %p6, %r2, %r32;\n"
    "       @%p6 bra        $LBB23_B2gCudaSearchBNDMq;\n"
    "       ld.param.u64    %rd5, [__cudaparm_B2gCudaSearchBNDMq_g_u8_lowercasetable];\n"
    "       ld.param.u64    %rd6, [__cudaparm_B2gCudaSearchBNDMq_B2G];\n"
    "       ld.param.u64    %rd7, [__cudaparm_B2gCudaSearchBNDMq_buf];\n"
    "$Lt_0_11522:\n"
    " //<loop> Loop body line 57\n"
    "       .loc    15      57      0\n"
    "       add.u32         %r33, %r10, %r3;\n"
    "       cvt.u64.u32     %rd8, %r33;\n"
    "       add.u64         %rd9, %rd8, %rd7;\n"
    "       ld.global.u8    %rh1, [%rd9+0];\n"
    "       cvt.u64.u8      %rd10, %rh1;\n"
    "       add.u64         %rd11, %rd10, %rd5;\n"
    "       ld.global.u8    %r34, [%rd11+0];\n"
    "       ld.global.u8    %rh2, [%rd9+-1];\n"
    "       cvt.u64.u8      %rd12, %rh2;\n"
    "       add.u64         %rd13, %rd12, %rd5;\n"
    "       ld.global.u8    %r35, [%rd13+0];\n"
    "       shl.b32         %r36, %r35, 4;\n"
    "       or.b32  %r37, %r34, %r36;\n"
    "       cvt.u64.u32     %rd14, %r37;\n"
    "       mul.lo.u64      %rd15, %rd14, 4;\n"
    "       add.u64         %rd16, %rd6, %rd15;\n"
    "       ld.global.u32   %r38, [%rd16+0];\n"
    "       mov.u32         %r39, 0;\n"
    "       setp.eq.u32     %p7, %r38, %r39;\n"
    "       @%p7 bra        $Lt_0_258;\n"
    " //<loop> Part of loop body line 57, head labeled $Lt_0_11522\n"
    "       .loc    15      60      0\n"
    "       mov.s32         %r28, %r3;\n"
    "       .loc    15      61      0\n"
    "       sub.u32         %r40, %r3, %r1;\n"
    "       add.u32         %r41, %r40, 1;\n"
    "       sub.s32         %r42, %r1, 1;\n"
    "$Lt_0_12546:\n"
    " //<loop> Loop body line 64\n"
    "       .loc    15      64      0\n"
    "       sub.u32         %r28, %r28, 1;\n"
    "       shr.u32         %r43, %r38, %r42;\n"
    "       mov.u32         %r44, 0;\n"
    "       setp.eq.u32     %p8, %r43, %r44;\n"
    "       @%p8 bra        $Lt_0_13314;\n"
    " //<loop> Part of loop body line 64, head labeled $Lt_0_12546\n"
    "       setp.ge.u32     %p9, %r41, %r28;\n"
    "       @%p9 bra        $Lt_0_13570;\n"
    " //<loop> Part of loop body line 64, head labeled $Lt_0_12546\n"
    "       .loc    15      67      0\n"
    "       mov.s32         %r3, %r28;\n"
    "       bra.uni         $Lt_0_13314;\n"
    "$Lt_0_13570:\n"
    " //<loop> Part of loop body line 64, head labeled $Lt_0_12546\n"
    "       .loc    15      69      0\n"
    "       mov.u32         %r45, 1;\n"
    "       ld.param.u64    %rd17, [__cudaparm_B2gCudaSearchBNDMq_offsets];\n"
    "       add.u32         %r46, %r10, %r28;\n"
    "       cvt.u64.u32     %rd18, %r46;\n"
    "       mul.lo.u64      %rd19, %rd18, 4;\n"
    "       add.u64         %rd20, %rd17, %rd19;\n"
    "       st.global.u32   [%rd20+0], %r45;\n"
    "$Lt_0_13314:\n"
    "$Lt_0_12802:\n"
    " //<loop> Part of loop body line 64, head labeled $Lt_0_12546\n"
    "       .loc    15      74      0\n"
    "       mov.u32         %r47, 0;\n"
    "       setp.eq.u32     %p10, %r28, %r47;\n"
    "       @%p10 bra       $Lt_0_258;\n"
    "//<loop> Part of loop body line 64, head labeled $Lt_0_12546\n"
    "       .loc    15      77      0\n"
    "       add.u32         %r48, %r10, %r28;\n"
    "       cvt.u64.u32     %rd21, %r48;\n"
    "       add.u64         %rd22, %rd21, %rd7;\n"
    "       ld.global.u8    %rh3, [%rd22+0];\n"
    "       cvt.u64.u8      %rd23, %rh3;\n"
    "       add.u64         %rd24, %rd23, %rd5;\n"
    "       ld.global.u8    %r49, [%rd24+0];\n"
    "       ld.global.u8    %rh4, [%rd22+-1];\n"
    "       cvt.u64.u8      %rd25, %rh4;\n"
    "       add.u64         %rd26, %rd25, %rd5;\n"
    "       ld.global.u8    %r50, [%rd26+0];\n"
    "       shl.b32         %r51, %r50, 4;\n"
    "       or.b32  %r52, %r49, %r51;\n"
    "       cvt.u64.u32     %rd27, %r52;\n"
    "       mul.lo.u64      %rd28, %rd27, 4;\n"
    "       add.u64         %rd29, %rd6, %rd28;\n"
    "       ld.global.u32   %r53, [%rd29+0];\n"
    "       shl.b32         %r54, %r38, 1;\n"
    "       and.b32         %r38, %r53, %r54;\n"
    "       mov.u32         %r55, 0;\n"
    "       setp.ne.u32     %p11, %r38, %r55;\n"
    "       @%p11 bra       $Lt_0_12546;\n"
    "$Lt_0_258:\n"
    "$Lt_0_11778:\n"
    " //<loop> Part of loop body line 57, head labeled $Lt_0_11522\n"
    "       .loc    15      80      0\n"
    "       add.u32         %r56, %r3, %r1;\n"
    "       sub.u32         %r3, %r56, 1;\n"
    "       setp.ge.u32     %p12, %r32, %r3;\n"
    "       @%p12 bra       $Lt_0_11522;\n"
    "$LBB23_B2gCudaSearchBNDMq:\n"
    "       .loc    15      83      0\n"
    "       exit;\n"
    "$LDWend_B2gCudaSearchBNDMq:\n"
    "       } // B2gCudaSearchBNDMq\n"
    "\n";
#else
/**
 * \todo Optimize the kernel.  Also explore the options for compiling the
 *       *.cu file at compile/runtime.
 */
const char *b2g_cuda_ptx_image_32_bit =
    "	.version 1.4\n"
    "	.target sm_10, map_f64_to_f32\n"
    "	.entry B2gCudaSearchBNDMq (\n"
    "		.param .u32 __cudaparm_B2gCudaSearchBNDMq_offsets,\n"
    "		.param .u32 __cudaparm_B2gCudaSearchBNDMq_B2G,\n"
    "		.param .u32 __cudaparm_B2gCudaSearchBNDMq_g_u8_lowercasetable,\n"
    "		.param .u32 __cudaparm_B2gCudaSearchBNDMq_buf,\n"
    "		.param .u16 __cudaparm_B2gCudaSearchBNDMq_arg_buflen,\n"
    "		.param .u32 __cudaparm_B2gCudaSearchBNDMq_m)\n"
    "	{\n"
    "	.reg .u32 %r<81>;\n"
    "	.reg .pred %p<14>;\n"
    "	.loc	15	14	0\n"
    "$LBB1_B2gCudaSearchBNDMq:\n"
    "	.loc	15	16	0\n"
    "	ld.param.u32 	%r1, [__cudaparm_B2gCudaSearchBNDMq_m];\n"
    "	sub.u32 	%r2, %r1, 1;\n"
    "	mov.s32 	%r3, %r2;\n"
    "	.loc	15	22	0\n"
    "	ld.param.u16 	%r4, [__cudaparm_B2gCudaSearchBNDMq_arg_buflen];\n"
    "	shr.u32 	%r5, %r4, 4;\n"
    "	cvt.u16.u32 	%r6, %r5;\n"
    "	mov.s32 	%r7, %r6;\n"
    "	setp.ge.u32 	%p1, %r6, %r1;\n"
    "	@%p1 bra 	$Lt_0_8450;\n"
    "	.loc	15	27	0\n"
    "	cvt.u16.u32 	%r7, %r1;\n"
    "$Lt_0_8450:\n"
    "	cvt.u32.u16 	%r8, %tid.x;\n"
    "	mul.lo.u32 	%r9, %r7, %r8;\n"
    "	cvt.u16.u32 	%r10, %r9;\n"
    "	add.s32 	%r11, %r7, %r10;\n"
    "	setp.ge.s32 	%p2, %r4, %r11;\n"
    "	@%p2 bra 	$Lt_0_8962;\n"
    "	bra.uni 	$LBB23_B2gCudaSearchBNDMq;\n"
    "$Lt_0_8962:\n"
    "	.loc	15	33	0\n"
    "	mul24.lo.s32 	%r12, %r7, 2;\n"
    "	sub.s32 	%r13, %r12, 1;\n"
    "	mov.s32 	%r14, %r13;\n"
    "	cvt.u16.u32 	%r15, %r14;\n"
    "	mov.s32 	%r16, %r15;\n"
    "	add.s32 	%r17, %r10, %r15;\n"
    "	set.lt.u32.s32 	%r18, %r4, %r17;\n"
    "	neg.s32 	%r19, %r18;\n"
    "	mov.u32 	%r20, 15;\n"
    "	set.eq.u32.u32 	%r21, %r8, %r20;\n"
    "	neg.s32 	%r22, %r21;\n"
    "	or.b32 	%r23, %r19, %r22;\n"
    "	mov.u32 	%r24, 0;\n"
    "	setp.eq.s32 	%p3, %r23, %r24;\n"
    "	@%p3 bra 	$Lt_0_9474;\n"
    "	.loc	15	35	0\n"
    "	sub.u32 	%r25, %r4, %r9;\n"
    "	cvt.u16.u32 	%r16, %r25;\n"
    "$Lt_0_9474:\n"
    "	mov.u32 	%r26, 0;\n"
    "	setp.eq.u32 	%p4, %r16, %r26;\n"
    "	@%p4 bra 	$Lt_0_9986;\n"
    "	mov.s32 	%r27, %r16;\n"
    "	ld.param.u32 	%r28, [__cudaparm_B2gCudaSearchBNDMq_offsets];\n"
    "	mov.u32 	%r29, 0;\n"
    "	mov.s32 	%r30, %r27;\n"
    "$Lt_0_10498:\n"
    " //<loop> Loop body line 35, nesting depth: 1, estimated iterations: unknown\n"
    "	.loc	15	40	0\n"
    "	mov.u32 	%r31, 0;\n"
    "	add.u32 	%r32, %r10, %r29;\n"
    "	mul.lo.u32 	%r33, %r32, 4;\n"
    "	add.u32 	%r34, %r28, %r33;\n"
    "	st.global.u32 	[%r34+0], %r31;\n"
    "	add.u32 	%r29, %r29, 1;\n"
    "	setp.ne.u32 	%p5, %r16, %r29;\n"
    "	@%p5 bra 	$Lt_0_10498;\n"
    "$Lt_0_9986:\n"
    "	sub.u32 	%r35, %r16, 1;\n"
    "	setp.gt.u32 	%p6, %r2, %r35;\n"
    "	@%p6 bra 	$LBB23_B2gCudaSearchBNDMq;\n"
    "	ld.param.u32 	%r36, [__cudaparm_B2gCudaSearchBNDMq_g_u8_lowercasetable];\n"
    "	ld.param.u32 	%r37, [__cudaparm_B2gCudaSearchBNDMq_B2G];\n"
    "	ld.param.u32 	%r38, [__cudaparm_B2gCudaSearchBNDMq_buf];\n"
    "$Lt_0_11522:\n"
    " //<loop> Loop body line 46\n"
    "	.loc	15	46	0\n"
    "	add.u32 	%r39, %r10, %r3;\n"
    "	add.u32 	%r40, %r39, %r38;\n"
    "	ld.global.u8 	%r41, [%r40+0];\n"
    "	add.u32 	%r42, %r41, %r36;\n"
    "	ld.global.u8 	%r43, [%r42+0];\n"
    "	ld.global.u8 	%r44, [%r40+-1];\n"
    "	add.u32 	%r45, %r44, %r36;\n"
    "	ld.global.u8 	%r46, [%r45+0];\n"
    "	shl.b32 	%r47, %r46, 4;\n"
    "	or.b32 	%r48, %r43, %r47;\n"
    "	mul.lo.u32 	%r49, %r48, 4;\n"
    "	add.u32 	%r50, %r37, %r49;\n"
    "	ld.global.u32 	%r51, [%r50+0];\n"
    "	mov.u32 	%r52, 0;\n"
    "	setp.eq.u32 	%p7, %r51, %r52;\n"
    "	@%p7 bra 	$Lt_0_258;\n"
    " //<loop> Part of loop body line 46, head labeled $Lt_0_11522\n"
    "	.loc	15	49	0\n"
    "	mov.s32 	%r29, %r3;\n"
    "	.loc	15	50	0\n"
    "	sub.u32 	%r53, %r3, %r1;\n"
    "	add.u32 	%r54, %r53, 1;\n"
    "	sub.s32 	%r55, %r1, 1;\n"
    "$Lt_0_12546:\n"
    " //<loop> Loop body line 53\n"
    "	.loc	15	53	0\n"
    "	sub.u32 	%r29, %r29, 1;\n"
    "	shr.u32 	%r56, %r51, %r55;\n"
    "	mov.u32 	%r57, 0;\n"
    "	setp.eq.u32 	%p8, %r56, %r57;\n"
    "	@%p8 bra 	$Lt_0_13314;\n"
    " //<loop> Part of loop body line 53, head labeled $Lt_0_12546\n"
    "	setp.ge.u32 	%p9, %r54, %r29;\n"
    "	@%p9 bra 	$Lt_0_13570;\n"
    " //<loop> Part of loop body line 53, head labeled $Lt_0_12546\n"
    "	.loc	15	56	0\n"
    "	mov.s32 	%r3, %r29;\n"
    "	bra.uni 	$Lt_0_13314;\n"
    "$Lt_0_13570:\n"
    " //<loop> Part of loop body line 53, head labeled $Lt_0_12546\n"
    "	.loc	15	58	0\n"
    "	mov.u32 	%r58, 1;\n"
    "	ld.param.u32 	%r59, [__cudaparm_B2gCudaSearchBNDMq_offsets];\n"
    "	add.u32 	%r60, %r10, %r29;\n"
    "	mul.lo.u32 	%r61, %r60, 4;\n"
    "	add.u32 	%r62, %r59, %r61;\n"
    "	st.global.u32 	[%r62+0], %r58;\n"
    "$Lt_0_13314:\n"
    "$Lt_0_12802:\n"
    " //<loop> Part of loop body line 53, head labeled $Lt_0_12546\n"
    "	.loc	15	63	0\n"
    "	mov.u32 	%r63, 0;\n"
    "	setp.eq.u32 	%p10, %r29, %r63;\n"
    "	@%p10 bra 	$Lt_0_258;\n"
    " //<loop> Part of loop body line 53, head labeled $Lt_0_12546\n"
    "	.loc	15	66	0\n"
    "	add.u32 	%r64, %r10, %r29;\n"
    "	add.u32 	%r65, %r64, %r38;\n"
    "	ld.global.u8 	%r66, [%r65+0];\n"
    "	add.u32 	%r67, %r66, %r36;\n"
    "	ld.global.u8 	%r68, [%r67+0];\n"
    "	ld.global.u8 	%r69, [%r65+-1];\n"
    "	add.u32 	%r70, %r69, %r36;\n"
    "	ld.global.u8 	%r71, [%r70+0];\n"
    "	shl.b32 	%r72, %r71, 4;\n"
    "	or.b32 	%r73, %r68, %r72;\n"
    "	mul.lo.u32 	%r74, %r73, 4;\n"
    "	add.u32 	%r75, %r37, %r74;\n"
    "	ld.global.u32 	%r76, [%r75+0];\n"
    "	shl.b32 	%r77, %r51, 1;\n"
    "	and.b32 	%r51, %r76, %r77;\n"
    "	mov.u32 	%r78, 0;\n"
    "	setp.ne.u32 	%p11, %r51, %r78;\n"
    "	@%p11 bra 	$Lt_0_12546;\n"
    "$Lt_0_258:\n"
    "$Lt_0_11778:\n"
    " //<loop> Part of loop body line 46, head labeled $Lt_0_11522\n"
    "	.loc	15	69	0\n"
    "	add.u32 	%r79, %r3, %r1;\n"
    "	sub.u32 	%r3, %r79, 1;\n"
    "	setp.ge.u32 	%p12, %r35, %r3;\n"
    "	@%p12 bra 	$Lt_0_11522;\n"
    "$LBB23_B2gCudaSearchBNDMq:\n"
    "	.loc	15	72	0\n"
    "	exit;\n"
    "$LDWend_B2gCudaSearchBNDMq:\n"
    "	} // B2gCudaSearchBNDMq\n"
    "\n";
#endif

/**
 * \brief Register the CUDA B2g Mpm.
 */
void MpmB2gCudaRegister(void)
{
    mpm_table[MPM_B2G_CUDA].name = "b2g_cuda";
    mpm_table[MPM_B2G_CUDA].max_pattern_length = B2G_CUDA_WORD_SIZE;

    mpm_table[MPM_B2G_CUDA].InitCtx = B2gCudaInitCtx;
    mpm_table[MPM_B2G_CUDA].InitThreadCtx = B2gCudaThreadInitCtx;
    mpm_table[MPM_B2G_CUDA].DestroyCtx = B2gCudaDestroyCtx;
    mpm_table[MPM_B2G_CUDA].DestroyThreadCtx = B2gCudaThreadDestroyCtx;
    mpm_table[MPM_B2G_CUDA].AddPattern = B2gCudaAddPatternCS;
    mpm_table[MPM_B2G_CUDA].AddPatternNocase = B2gCudaAddPatternCI;
    mpm_table[MPM_B2G_CUDA].Prepare = B2gCudaPreparePatterns;
    mpm_table[MPM_B2G_CUDA].Search = B2gCudaSearchWrap;
    mpm_table[MPM_B2G_CUDA].Cleanup = NULL;
    mpm_table[MPM_B2G_CUDA].PrintCtx = B2gCudaPrintInfo;
    mpm_table[MPM_B2G_CUDA].PrintThreadCtx = B2gCudaPrintSearchStats;
    mpm_table[MPM_B2G_CUDA].RegisterUnittests = B2gCudaRegisterTests;
}

static inline void B2gCudaEndMatchAppend(MpmCtx *mpm_ctx, B2gCudaPattern *p,
                                         uint16_t offset, uint16_t depth,
                                         uint32_t pid, uint32_t sid)
{
    MpmEndMatch *em = MpmAllocEndMatch(mpm_ctx);
    if (em == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        return;
    }

    SCLogDebug("em alloced at %p", em);

    em->id = pid;
    em->sig_id = sid;
    em->depth = depth;
    em->offset = offset;

    if (p->em == NULL) {
        p->em = em;
        return;
    }

    MpmEndMatch *m = p->em;
    while (m->next != NULL) {
        m = m->next;
    }
    m->next = em;

    return;
}

void B2gCudaPrintInfo(MpmCtx *mpm_ctx)
{
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx->ctx;

    SCLogDebug("MPM B2g Cuda Information:");
    SCLogDebug("Memory allocs:    %" PRIu32, mpm_ctx->memory_cnt);
    SCLogDebug("Memory alloced:   %" PRIu32, mpm_ctx->memory_size);
    SCLogDebug(" Sizeofs:");
    SCLogDebug("  MpmCtx          %" PRIuMAX, (uintmax_t)sizeof(MpmCtx));
    SCLogDebug("  B2gCudaCtx      %" PRIuMAX, (uintmax_t)sizeof(B2gCudaCtx));
    SCLogDebug("  B2gCudaPattern  %" PRIuMAX, (uintmax_t)sizeof(B2gCudaPattern));
    SCLogDebug("  B2gCudaHashItem %" PRIuMAX, (uintmax_t)sizeof(B2gCudaHashItem));
    SCLogDebug("Unique Patterns:  %" PRIu32, mpm_ctx->pattern_cnt);
    SCLogDebug("Total Patterns:   %" PRIu32, mpm_ctx->total_pattern_cnt);
    SCLogDebug("Smallest:         %" PRIu32, mpm_ctx->minlen);
    SCLogDebug("Largest:          %" PRIu32, mpm_ctx->maxlen);
    SCLogDebug("Hash size:        %" PRIu32, ctx->hash_size);

    return;
}

static inline B2gCudaPattern *B2gCudaAllocPattern(MpmCtx *mpm_ctx)
{
    B2gCudaPattern *p = SCMalloc(sizeof(B2gCudaPattern));
    if (p == NULL)
        return NULL;
    memset(p, 0, sizeof(B2gCudaPattern));

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(B2gCudaPattern);

    return p;
}

static inline B2gCudaHashItem *B2gCudaAllocHashItem(MpmCtx *mpm_ctx)
{
    B2gCudaHashItem *hi = SCMalloc(sizeof(B2gCudaHashItem));
    if (hi == NULL)
        return NULL;
    memset(hi, 0, sizeof(B2gCudaHashItem));

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(B2gCudaHashItem);

    return hi;
}

static void B2gCudaHashFree(MpmCtx *mpm_ctx, B2gCudaHashItem *hi)
{
    if (hi == NULL)
        return;

    B2gCudaHashItem *t = hi->nxt;
    B2gCudaHashFree(mpm_ctx, t);

    mpm_ctx->memory_cnt--;
    mpm_ctx->memory_size -= sizeof(B2gCudaHashItem);
    SCFree(hi);

    return;
}

static inline void memcpy_tolower(uint8_t *d, uint8_t *s, uint16_t len)
{
    uint16_t i;
    for (i = 0; i < len; i++)
        d[i] = u8_tolower(s[i]);

    return;
}

static inline uint32_t B2gCudaInitHash(B2gCudaPattern *p)
{
    uint32_t hash = p->len * p->cs[0];
    if (p->len > 1)
        hash += p->cs[1];

    return (hash % INIT_HASH_SIZE);
}

static inline uint32_t B2gCudaInitHashRaw(uint8_t *pat, uint16_t patlen)
{
    uint32_t hash = patlen * pat[0];
    if (patlen > 1)
        hash += pat[1];

    return (hash % INIT_HASH_SIZE);
}

static inline int B2gCudaInitHashAdd(B2gCudaCtx *ctx, B2gCudaPattern *p)
{
    uint32_t hash = B2gCudaInitHash(p);

    if (ctx->init_hash[hash] == NULL) {
        ctx->init_hash[hash] = p;
        return 0;
    }

    B2gCudaPattern *tt = NULL;
    B2gCudaPattern *t = ctx->init_hash[hash];

    /* get the list tail */
    do {
        tt = t;
        t = t->next;
    } while (t != NULL);

    tt->next = p;

    return 0;
}

static inline int B2gCudaCmpPattern(B2gCudaPattern *p, uint8_t *pat,
                                    uint16_t patlen, char flags)
{
    if (p->len != patlen)
        return 0;

    if (p->flags != flags)
        return 0;

    if (memcmp(p->cs, pat, patlen) != 0)
        return 0;

    return 1;
}

static inline B2gCudaPattern *B2gCudaInitHashLookup(B2gCudaCtx *ctx, uint8_t *pat,
                                                    uint16_t patlen, char flags)
{
    uint32_t hash = B2gCudaInitHashRaw(pat, patlen);

    if (ctx->init_hash[hash] == NULL)
        return NULL;

    B2gCudaPattern *t = ctx->init_hash[hash];
    for ( ; t != NULL; t = t->next) {
        if (B2gCudaCmpPattern(t, pat, patlen, flags) == 1)
            return t;
    }

    return NULL;
}

void B2gCudaFreePattern(MpmCtx *mpm_ctx, B2gCudaPattern *p)
{
    if (p != NULL && p->em != NULL)
        MpmEndMatchFreeAll(mpm_ctx, p->em);

    if (p != NULL && p->cs != NULL && p->cs != p->ci) {
        SCFree(p->cs);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= p->len;
    }

    if (p != NULL && p->ci != NULL) {
        SCFree(p->ci);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= p->len;
    }

    if (p != NULL) {
        SCFree(p);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= sizeof(B2gCudaPattern);
    }

    return;
}

static inline int B2gCudaAddPattern(MpmCtx *mpm_ctx, uint8_t *pat,
                                    uint16_t patlen, uint16_t offset,
                                    uint16_t depth, uint32_t pid,
                                    uint32_t sid, uint8_t flags)
{
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx->ctx;

    SCLogDebug("ctx %p len %" PRIu16 " pid %" PRIu32, ctx, patlen, pid);

    if (patlen == 0)
        return 0;

    /* get a memory piece */
    B2gCudaPattern *p = B2gCudaInitHashLookup(ctx, pat, patlen, flags);
    if (p == NULL) {
        SCLogDebug("allocing new pattern");

        p = B2gCudaAllocPattern(mpm_ctx);
        if (p == NULL)
            goto error;

        p->len = patlen;
        p->flags = flags;

        /* setup the case insensitive part of the pattern */
        p->ci = SCMalloc(patlen);
        if (p->ci == NULL)
            goto error;
        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size += patlen;
        memcpy_tolower(p->ci, pat, patlen);

        /* setup the case sensitive part of the pattern */
        if (p->flags & MPM_PATTERN_FLAG_NOCASE) {
            /* nocase means no difference between cs and ci */
            p->cs = p->ci;
        } else {
            if (memcmp(p->ci, pat, p->len) == 0) {
                /* no diff between cs and ci: pat is lowercase */
                p->cs = p->ci;
            } else {
                p->cs = SCMalloc(patlen);
                if (p->cs == NULL)
                    goto error;

                mpm_ctx->memory_cnt++;
                mpm_ctx->memory_size += patlen;

                memcpy(p->cs, pat, patlen);
            }
        }

        /* put in the pattern hash */
        B2gCudaInitHashAdd(ctx, p);

        if (mpm_ctx->pattern_cnt == 65535) {
            printf("Max search words reached\n");
            exit(EXIT_FAILURE);
        }
        mpm_ctx->pattern_cnt++;

        if (mpm_ctx->maxlen < patlen)
            mpm_ctx->maxlen = patlen;

        if (mpm_ctx->minlen == 0)
            mpm_ctx->minlen = patlen;
        else if (mpm_ctx->minlen > patlen)
            mpm_ctx->minlen = patlen;
    }

    /* we need a match */
    B2gCudaEndMatchAppend(mpm_ctx, p, offset, depth, pid, sid);

    mpm_ctx->total_pattern_cnt++;

    return 0;

error:
    B2gCudaFreePattern(mpm_ctx, p);
    return -1;
}

int B2gCudaAddPatternCI(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                        uint16_t offset, uint16_t depth, uint32_t pid,
                        uint32_t sid, uint8_t flags)
{
    flags |= MPM_PATTERN_FLAG_NOCASE;
    return B2gCudaAddPattern(mpm_ctx, pat, patlen, offset, depth, pid, sid, flags);
}

int B2gCudaAddPatternCS(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                        uint16_t offset, uint16_t depth, uint32_t pid,
                        uint32_t sid, uint8_t flags)
{
    return B2gCudaAddPattern(mpm_ctx, pat, patlen, offset, depth, pid, sid, flags);
}

static inline uint32_t B2gCudaBloomHash(void *data, uint16_t datalen, uint8_t iter,
                                        uint32_t hash_size)
{
     uint8_t *d = (uint8_t *)data;
     uint16_t i;
     uint32_t hash = (uint32_t)u8_tolower(*d);

     for (i = 1; i < datalen; i++) {
         d++;
         hash += (u8_tolower(*d)) ^ i;
     }
     hash <<= (iter+1);
     hash %= hash_size;

     return hash;
}

static void B2gCudaPrepareHash(MpmCtx *mpm_ctx)
{
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx->ctx;
    uint16_t i = 0;
    uint16_t idx = 0;
    uint8_t idx8 = 0;

    ctx->hash = (B2gCudaHashItem **)SCMalloc(sizeof(B2gCudaHashItem *) *
                                             ctx->hash_size);
    if (ctx->hash == NULL)
        goto error;
    memset(ctx->hash, 0, sizeof(B2gCudaHashItem *) * ctx->hash_size);

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (sizeof(B2gCudaHashItem *) * ctx->hash_size);

#ifdef B2G_CUDA_SEARCH2
    ctx->hash2 = (B2gCudaHashItem **)SCMalloc(sizeof(B2gCudaHashItem *) *
                                              ctx->hash_size);
    if (ctx->hash2 == NULL)
        goto error;
    memset(ctx->hash2, 0, sizeof(B2gCudaHashItem *) * ctx->hash_size);

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (sizeof(B2gCudaHashItem *) * ctx->hash_size);
#endif

    /* alloc the pminlen array */
    ctx->pminlen = (uint8_t *)SCMalloc(sizeof(uint8_t) * ctx->hash_size);
    if (ctx->pminlen == NULL)
        goto error;
    memset(ctx->pminlen, 0, sizeof(uint8_t) * ctx->hash_size);

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (sizeof(uint8_t) * ctx->hash_size);

    for (i = 0; i < mpm_ctx->pattern_cnt; i++)
    {
        if(ctx->parray[i]->len == 1) {
            idx8 = (uint8_t)ctx->parray[i]->ci[0];
            if (ctx->hash1[idx8].flags == 0) {
                ctx->hash1[idx8].idx = i;
                ctx->hash1[idx8].flags |= 0x01;
            } else {
                B2gCudaHashItem *hi = B2gCudaAllocHashItem(mpm_ctx);
                if (hi == NULL)
                    goto error;
                hi->idx = i;
                hi->flags |= 0x01;

                /* Append this HashItem to the list */
                B2gCudaHashItem *thi = &ctx->hash1[idx8];
                while (thi->nxt)
                    thi = thi->nxt;
                thi->nxt = hi;
            }
            ctx->pat_1_cnt++;
#ifdef B2G_CUDA_SEARCH2
        } else if(ctx->parray[i]->len == 2) {
            idx = B2G_CUDA_HASH16(ctx->parray[i]->ci[0], ctx->parray[i]->ci[1]);
            if (ctx->hash2[idx] == NULL) {
                B2gCudaHashItem *hi = B2gCudaAllocHashItem(mpm_ctx);
                if (hi == NULL)
                    goto error;
                hi->idx = i;
                hi->flags |= 0x01;

                ctx->hash2[idx] = hi;
            } else {
                B2gCudaHashItem *hi = B2gCudaAllocHashItem(mpm_ctx);
                if (hi == NULL)
                    goto error;
                hi->idx = i;
                hi->flags |= 0x01;

                /* Append this HashItem to the list */
                B2gCudaHashItem *thi = ctx->hash2[idx];
                while (thi->nxt)
                    thi = thi->nxt;
                thi->nxt = hi;
            }
            ctx->pat_2_cnt++;
#endif
        } else {
            idx = B2G_CUDA_HASH16(ctx->parray[i]->ci[ctx->m - 2],
                             ctx->parray[i]->ci[ctx->m - 1]);
            SCLogDebug("idx %" PRIu32 ", %c.%c", idx, ctx->parray[i]->ci[ctx->m - 2],
                       ctx->parray[i]->ci[ctx->m - 1]);

            if (ctx->hash[idx] == NULL) {
                B2gCudaHashItem *hi = B2gCudaAllocHashItem(mpm_ctx);
                if (hi == NULL)
                    goto error;
                hi->idx = i;
                hi->flags |= 0x01;
                ctx->pminlen[idx] = ctx->parray[i]->len;

                ctx->hash[idx] = hi;
            } else {
                B2gCudaHashItem *hi = B2gCudaAllocHashItem(mpm_ctx);
                if (hi == NULL)
                    goto error;
                hi->idx = i;
                hi->flags |= 0x01;

                if (ctx->parray[i]->len < ctx->pminlen[idx])
                    ctx->pminlen[idx] = ctx->parray[i]->len;

                /* Append this HashItem to the list */
                B2gCudaHashItem *thi = ctx->hash[idx];
                while (thi->nxt)
                    thi = thi->nxt;
                thi->nxt = hi;
            }
            ctx->pat_x_cnt++;
        }
    }

    /* alloc the bloom array */
    ctx->bloom = (BloomFilter **)SCMalloc(sizeof(BloomFilter *) * ctx->hash_size);
    if (ctx->bloom == NULL)
        goto error;
    memset(ctx->bloom, 0, sizeof(BloomFilter *) * ctx->hash_size);

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (sizeof(BloomFilter *) * ctx->hash_size);

    uint32_t h;
    for (h = 0; h < ctx->hash_size; h++) {
        B2gCudaHashItem *hi = ctx->hash[h];
        if (hi == NULL)
            continue;

        ctx->bloom[h] = BloomFilterInit(b2g_bloom_size, 2, B2gCudaBloomHash);
        if (ctx->bloom[h] == NULL)
            continue;

        mpm_ctx->memory_cnt += BloomFilterMemoryCnt(ctx->bloom[h]);
        mpm_ctx->memory_size += BloomFilterMemorySize(ctx->bloom[h]);

        if (ctx->pminlen[h] > 8)
            ctx->pminlen[h] = 8;

        B2gCudaHashItem *thi = hi;
        do {
            SCLogDebug("adding \"%c%c\" to the bloom", ctx->parray[thi->idx]->ci[0],
                       ctx->parray[thi->idx]->ci[1]);
            BloomFilterAdd(ctx->bloom[h], ctx->parray[thi->idx]->ci,
                           ctx->pminlen[h]);
            thi = thi->nxt;
        } while (thi != NULL);
    }

    return;

error:
    return;
}

int B2gCudaBuildMatchArray(MpmCtx *mpm_ctx)
{
    SCEnter();
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx->ctx;

    ctx->B2G = SCMalloc(sizeof(B2G_CUDA_TYPE) * ctx->hash_size);
    if (ctx->B2G == NULL)
        return -1;

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (sizeof(B2G_CUDA_TYPE) * ctx->hash_size);

    memset(ctx->B2G, 0, b2g_hash_size * sizeof(B2G_CUDA_TYPE));

    uint32_t j;
    uint32_t a;

    /* fill the match array */
    for (j = 0; j <= (ctx->m - B2G_CUDA_Q); j++) {
        for (a = 0; a < mpm_ctx->pattern_cnt; a++) {
            if (ctx->parray[a]->len < ctx->m)
                continue;

            uint16_t h = B2G_CUDA_HASH16(u8_tolower(ctx->parray[a]->ci[j]),
                                         u8_tolower(ctx->parray[a]->ci[j + 1]));
            ctx->B2G[h] = ctx->B2G[h] | (1 << (ctx->m - j));

            SCLogDebug("h %" PRIu16 ", ctx->B2G[h] %" PRIu32, h, ctx->B2G[h]);
        }
    }

    ctx->s0 = 1;

    SCReturnInt(0);
}

int B2gCudaSetDeviceBuffers(MpmCtx *mpm_ctx)
{
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx->ctx;

    if (SCCudaHlGetCudaDevicePtr(&ctx->cuda_g_u8_lowercasetable,
                                 "G_U8_LOWERCASETABLE", 256 * sizeof(char),
                                 g_u8_lowercasetable, ctx->module_handle) == -1) {
        goto error;
    }

    /* search kernel */
    if (SCCudaMemAlloc(&ctx->cuda_B2G,
                       sizeof(B2G_CUDA_TYPE) * ctx->hash_size) == -1) {
        goto error;
    }
    if (SCCudaMemcpyHtoD(ctx->cuda_B2G, ctx->B2G,
                         sizeof(B2G_CUDA_TYPE) * ctx->hash_size) == -1) {
        goto error;
    }

    return 0;

 error:
    return -1;
}

int B2gCudaSetKernelArgs(MpmCtx *mpm_ctx)
{
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx->ctx;

    /* search kernel */
    if (SCCudaParamSetv(ctx->cuda_search_kernel, ctx->cuda_search_kernel_arg2_offset,
                        (void *)&ctx->cuda_g_u8_lowercasetable,
                        sizeof(void *)) == -1) {
        goto error;
    }

    return 0;

 error:
    return -1;
}

int B2gCudaPreparePatterns(MpmCtx *mpm_ctx)
{
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx->ctx;

    /* alloc the pattern array */
    ctx->parray = (B2gCudaPattern **)SCMalloc(mpm_ctx->pattern_cnt *
                                              sizeof(B2gCudaPattern *));
    if (ctx->parray == NULL)
        goto error;
    memset(ctx->parray, 0, mpm_ctx->pattern_cnt * sizeof(B2gCudaPattern *));

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (mpm_ctx->pattern_cnt * sizeof(B2gCudaPattern *));

    /* populate it with the patterns in the hash */
    uint32_t i = 0, p = 0;
    for (i = 0; i < INIT_HASH_SIZE; i++) {
        B2gCudaPattern *node = ctx->init_hash[i];
        B2gCudaPattern *nnode = NULL;
        for ( ; node != NULL; ) {
            nnode = node->next;
            node->next = NULL;

            ctx->parray[p] = node;

            p++;
            node = nnode;
        }
    }
    /* we no longer need the hash, so free it's memory */
    SCFree(ctx->init_hash);
    ctx->init_hash = NULL;

    /* set 'm' to the smallest pattern size */
    ctx->m = mpm_ctx->minlen;

    /* make sure 'm' stays in bounds
       m can be max WORD_SIZE - 1 */
    if (ctx->m >= B2G_CUDA_WORD_SIZE) {
        ctx->m = B2G_CUDA_WORD_SIZE - 1;
    }
    if (ctx->m < 2)
        ctx->m = 2;

    ctx->hash_size = b2g_hash_size;
    B2gCudaPrepareHash(mpm_ctx);
    B2gCudaBuildMatchArray(mpm_ctx);

    if (B2gCudaSetDeviceBuffers(mpm_ctx) == -1)
        goto error;

    if (B2gCudaSetKernelArgs(mpm_ctx) == -1)
        goto error;

    SCLogDebug("ctx->pat_1_cnt %" PRIu16, ctx->pat_1_cnt);
    if (ctx->pat_1_cnt) {
        ctx->Search = B2gCudaSearch1;
#ifdef B2G_CUDA_SEARCH2
        ctx->Search = B2gCudaSearch2;
        if (ctx->pat_2_cnt) {
            ctx->MBSearch2 = B2gCudaSearch2;
        }
#endif
        ctx->MBSearch = b2g_func;
#ifdef B2G_SEARCH2
    } else if (ctx->pat_2_cnt) {
        ctx->Search = B2gSearch2;
        ctx->MBSearch = b2g_cuda_func;
#endif
    }

    return 0;

 error:
    return -1;
}

void B2gCudaPrintSearchStats(MpmThreadCtx *mpm_thread_ctx)
{
#ifdef B2G_CUDA_COUNTERS
    B2gCudaThreadCtx *tctx = (B2gCudaThreadCtx *)mpm_thread_ctx->ctx;

    printf("B2g Thread Search stats (tctx %p)\n", tctx);
    printf("Total calls: %" PRIu32 "\n", tctx->stat_calls);
    printf("Avg m/search: %0.2f\n", (tctx->stat_calls ?
                                     (float)((float)tctx->stat_m_total /
                                             (float)tctx->stat_calls) : 0));
    printf("D != 0 (possible match): %" PRIu32 "\n", tctx->stat_d0);
    printf("Avg hash items per bucket %0.2f (%" PRIu32 ")\n",
           tctx->stat_d0 ? (float)((float)tctx->stat_d0_hashloop /
                                   (float)tctx->stat_d0) : 0,
           tctx->stat_d0_hashloop);
    printf("Loop match: %" PRIu32 "\n", tctx->stat_loop_match);
    printf("Loop no match: %" PRIu32 "\n", tctx->stat_loop_no_match);
    printf("Num shifts: %" PRIu32 "\n", tctx->stat_num_shift);
    printf("Total shifts: %" PRIu32 "\n", tctx->stat_total_shift);
    printf("Avg shifts: %0.2f\n", (tctx->stat_num_shift ?
                                   (float)((float)tctx->stat_total_shift /
                                           (float)tctx->stat_num_shift)) : 0);
    printf("Total BloomFilter checks: %" PRIu32 "\n", tctx->stat_bloom_calls);
    printf("BloomFilter hits: %0.4f%% (%" PRIu32 ")\n",
           (tctx->stat_bloom_calls ? ((float)tctx->stat_bloom_hits /
                                      (float)tctx->stat_bloom_calls) * 100) : 0,
           tctx->stat_bloom_hits);
    printf("Avg pminlen: %0.2f\n\n",
           (tctx->stat_pminlen_calls ? ((float)tctx->stat_pminlen_total /
                                        (float)tctx->stat_pminlen_calls)) : 0);
#endif /* B2G_CUDA_COUNTERS */

}

static inline int memcmp_lowercase(uint8_t *s1, uint8_t *s2, uint16_t n)
{
    size_t i;

    /* check backwards because we already tested the first
     * 2 to 4 chars. This way we are more likely to detect
     * a miss and thus speed up a little... */
    for (i = n - 1; i; i--) {
        if (u8_tolower(*(s2 + i)) != s1[i])
            return 1;
    }

    return 0;
}

/**
 * \brief   Function to get the user defined values for b2g algorithm from the
 *          config file 'suricata.yaml'
 */
static void B2gGetConfig()
{
    ConfNode *b2g_conf;
    const char *hash_val = NULL;
    const char *bloom_val = NULL;
    const char *algo = NULL;

    /* init defaults */
    b2g_hash_size = HASHSIZE_LOW;
    b2g_bloom_size = BLOOMSIZE_MEDIUM;
    b2g_func = B2G_CUDA_SEARCHFUNC;

    ConfNode *pm = ConfGetNode("pattern-matcher");

    if (pm != NULL) {

        TAILQ_FOREACH(b2g_conf, &pm->head, next) {
            if (strncmp(b2g_conf->val, "b2g", 3) == 0) {

                algo = ConfNodeLookupChildValue
                        (b2g_conf->head.tqh_first, "algo");
                hash_val = ConfNodeLookupChildValue
                        (b2g_conf->head.tqh_first, "hash_size");
                bloom_val = ConfNodeLookupChildValue
                        (b2g_conf->head.tqh_first, "bf_size");

                if (algo != NULL) {
                    if (strcmp(algo, "B2gSearch") == 0) {
                        b2g_func = B2gCudaSearch;
                    } else if (strcmp(algo, "B2gSearchBNDMq") == 0) {
                        b2g_func = B2gCudaSearchBNDMq;
                    }
                }

                if (hash_val != NULL)
                    b2g_hash_size = MpmGetHashSize(hash_val);

                if (bloom_val != NULL)
                    b2g_bloom_size = MpmGetBloomSize(bloom_val);

                SCLogDebug("hash size is %"PRIu32" and bloom size is %"PRIu32"",
                b2g_hash_size, b2g_bloom_size);
            }
        }
    }
}

void B2gCudaInitCtx(MpmCtx *mpm_ctx, int module_handle)
{
    SCLogDebug("mpm_ctx %p, ctx %p", mpm_ctx, mpm_ctx->ctx);

    BUG_ON(mpm_ctx->ctx != NULL);

    mpm_ctx->ctx = SCMalloc(sizeof(B2gCudaCtx));
    if (mpm_ctx->ctx == NULL)
        return;

    memset(mpm_ctx->ctx, 0, sizeof(B2gCudaCtx));

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(B2gCudaCtx);

    /* initialize the hash we use to speed up pattern insertions */
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx->ctx;
    ctx->module_handle = module_handle;

    ctx->init_hash = SCMalloc(sizeof(B2gCudaPattern *) * INIT_HASH_SIZE);
    if (ctx->init_hash == NULL)
        return;

    memset(ctx->init_hash, 0, sizeof(B2gCudaPattern *) * INIT_HASH_SIZE);

    /* Initialize the defaults value from the config file. The given check make
       sure that we query config file only once for config values */
    if (b2g_hash_size == 0)
        B2gGetConfig();

    /* init defaults search functions */
    ctx->Search = b2g_func;

    if (SCCudaHlGetCudaContext(&ctx->cuda_context, module_handle) == -1) {
        SCLogError(SC_ERR_B2G_CUDA_ERROR, "Error getting a cuda context");
    }

#if defined(__x86_64__) || defined(__ia64__)
    if (SCCudaHlGetCudaModule(&ctx->cuda_module, b2g_cuda_ptx_image_64_bit,
                              module_handle) == -1) {
        SCLogError(SC_ERR_B2G_CUDA_ERROR, "Error getting a cuda module");
    }
#else
    if (SCCudaHlGetCudaModule(&ctx->cuda_module, b2g_cuda_ptx_image_32_bit,
                              module_handle) == -1) {
        SCLogError(SC_ERR_B2G_CUDA_ERROR, "Error getting a cuda module");
    }
#endif


    if (SCCudaModuleGetFunction(&ctx->cuda_search_kernel, ctx->cuda_module,
                                B2G_CUDA_SEARCHFUNC_NAME) == -1) {
        SCLogError(SC_ERR_B2G_CUDA_ERROR, "Error getting a cuda function");
    }

#define ALIGN_UP(offset, alignment) (offset) = ((offset) + (alignment) - 1) & ~((alignment) - 1)

    int offset = 0;

    ALIGN_UP(offset, __alignof(void *));
    ctx->cuda_search_kernel_arg0_offset = offset;
    offset += sizeof(void *);

    ALIGN_UP(offset, __alignof(void *));
    ctx->cuda_search_kernel_arg1_offset = offset;
    offset += sizeof(void *);

    ALIGN_UP(offset, __alignof(void *));
    ctx->cuda_search_kernel_arg2_offset = offset;
    offset += sizeof(void *);

    ALIGN_UP(offset, __alignof(void *));
    ctx->cuda_search_kernel_arg3_offset = offset;
    offset += sizeof(void *);

    ALIGN_UP(offset, __alignof(unsigned short));
    ctx->cuda_search_kernel_arg4_offset = offset;
    offset += sizeof(unsigned short);

    ALIGN_UP(offset, __alignof(unsigned int));
    ctx->cuda_search_kernel_arg5_offset = offset;
    offset += sizeof(unsigned int);

    ctx->cuda_search_kernel_arg_total = offset;

    //printf("arg0: %d\n", arg0);
    //printf("arg1: %d\n", arg1);
    //printf("arg2: %d\n", arg2);
    //printf("arg3: %d\n", arg3);
    //printf("arg4: %d\n", arg4);
    //printf("arg5: %d\n", arg5);

    //printf("arg_total: %d\n", arg_total);

    return;
}

void B2gCudaDestroyCtx(MpmCtx *mpm_ctx)
{
    SCLogDebug("mpm_ctx %p", mpm_ctx);

    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx->ctx;
    if (ctx == NULL)
        return;

    if (ctx->init_hash) {
        SCFree(ctx->init_hash);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (INIT_HASH_SIZE * sizeof(B2gCudaPattern *));
    }

    if (ctx->parray) {
        uint32_t i;
        for (i = 0; i < mpm_ctx->pattern_cnt; i++) {
            if (ctx->parray[i] != NULL) {
                B2gCudaFreePattern(mpm_ctx, ctx->parray[i]);
            }
        }

        SCFree(ctx->parray);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (mpm_ctx->pattern_cnt * sizeof(B2gCudaPattern));
    }

    if (ctx->B2G) {
        SCFree(ctx->B2G);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (sizeof(B2G_CUDA_TYPE) * ctx->hash_size);
    }

    if (ctx->bloom) {
        uint32_t h;
        for (h = 0; h < ctx->hash_size; h++) {
            if (ctx->bloom[h] == NULL)
                continue;

            mpm_ctx->memory_cnt -= BloomFilterMemoryCnt(ctx->bloom[h]);
            mpm_ctx->memory_size -= BloomFilterMemorySize(ctx->bloom[h]);

            BloomFilterFree(ctx->bloom[h]);
        }

        SCFree(ctx->bloom);

        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (sizeof(BloomFilter *) * ctx->hash_size);
    }

    if (ctx->hash) {
        uint32_t h;
        for (h = 0; h < ctx->hash_size; h++) {
            if (ctx->hash[h] == NULL)
                continue;

            B2gCudaHashFree(mpm_ctx, ctx->hash[h]);
        }

        SCFree(ctx->hash);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (sizeof(B2gCudaHashItem) * ctx->hash_size);
    }

    if (ctx->pminlen) {
        SCFree(ctx->pminlen);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (sizeof(uint8_t) * ctx->hash_size);
    }

    if (ctx->cuda_B2G != 0) {
        if (SCCudaMemFree(ctx->cuda_B2G) == -1)
            SCLogError(SC_ERR_B2G_CUDA_ERROR, "Error freeing ctx->cuda_search_B2G ");
        ctx->cuda_B2G = 0;
    }

    SCFree(mpm_ctx->ctx);
    mpm_ctx->memory_cnt--;
    mpm_ctx->memory_size -= sizeof(B2gCudaCtx);

    return;
}

void B2gCudaThreadInitCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                          uint32_t matchsize)
{
    memset(mpm_thread_ctx, 0, sizeof(MpmThreadCtx));

    /* size can be null when optimized */
    if (sizeof(B2gCudaThreadCtx) > 0) {
        mpm_thread_ctx->ctx = SCMalloc(sizeof(B2gCudaThreadCtx));
        if (mpm_thread_ctx->ctx == NULL)
            return;

        memset(mpm_thread_ctx->ctx, 0, sizeof(B2gCudaThreadCtx));

        mpm_thread_ctx->memory_cnt++;
        mpm_thread_ctx->memory_size += sizeof(B2gCudaThreadCtx);
    }

    return;
}

void B2gCudaThreadDestroyCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx)
{
    B2gCudaThreadCtx *ctx = (B2gCudaThreadCtx *)mpm_thread_ctx->ctx;

    B2gCudaPrintSearchStats(mpm_thread_ctx);

    /* can be NULL if B2gThreadCtx is optimized to 0 */
    if (ctx != NULL) {
        mpm_thread_ctx->memory_cnt--;
        mpm_thread_ctx->memory_size -= sizeof(B2gCudaThreadCtx);
        SCFree(mpm_thread_ctx->ctx);
    }

    return;
}

inline uint32_t B2gCudaSearchWrap(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                                  PatternMatcherQueue *pmq, uint8_t *buf,
                                  uint16_t buflen)
{
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx->ctx;
    return ctx ? ctx->Search(mpm_ctx, mpm_thread_ctx, pmq, buf, buflen) : 0;
}

uint32_t B2gCudaSearchBNDMq(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                            PatternMatcherQueue *pmq, uint8_t *buf,
                            uint16_t buflen)
{
#define CUDA_THREADS 16
    CUdeviceptr cuda_buf = 0;
    CUdeviceptr cuda_offsets = 0;
    uint32_t matches = 0;
    B2gCudaCtx *ctx = mpm_ctx->ctx;
    uint16_t h = 0;
    int i = 0;
    int host_offsets[UINT16_MAX];

    if (buflen < ctx->m)
        return 0;

    if (SCCudaMemAlloc(&cuda_buf, buflen * sizeof(char)) == -1) {
        goto error;
    }
    if (SCCudaMemcpyHtoD(cuda_buf, buf,
                         buflen * sizeof(char)) == -1) {
        goto error;
    }

    if (SCCudaMemAlloc(&cuda_offsets, buflen * sizeof(int)) == -1) {
        goto error;
    }

    if (SCCudaParamSetv(ctx->cuda_search_kernel, ctx->cuda_search_kernel_arg0_offset,
                        (void *)&cuda_offsets, sizeof(void *)) == -1) {
        goto error;
    }

    if (SCCudaParamSetv(ctx->cuda_search_kernel, ctx->cuda_search_kernel_arg1_offset,
                        (void *)&ctx->cuda_B2G, sizeof(void *)) == -1) {
        goto error;
    }

    if (SCCudaParamSetv(ctx->cuda_search_kernel, ctx->cuda_search_kernel_arg3_offset,
                        (void *)&cuda_buf, sizeof(void *)) == -1) {
        goto error;
    }

    if (SCCudaParamSeti(ctx->cuda_search_kernel, ctx->cuda_search_kernel_arg4_offset,
                        buflen) == -1) {
        goto error;
    }

    if (SCCudaParamSeti(ctx->cuda_search_kernel, ctx->cuda_search_kernel_arg5_offset,
                        ctx->m) == -1) {
        goto error;
    }

    if (SCCudaParamSetSize(ctx->cuda_search_kernel, ctx->cuda_search_kernel_arg_total) == -1)
        goto error;

    if (SCCudaFuncSetBlockShape(ctx->cuda_search_kernel, CUDA_THREADS, 1, 1) == -1)
        goto error;

    if (SCCudaLaunchGrid(ctx->cuda_search_kernel, 1, 1) == -1)
        goto error;

    if (SCCudaMemcpyDtoH(host_offsets, cuda_offsets, buflen * sizeof(int)) == -1)
        goto error;

    //printf("Raw matches: ");
    //for (i = 0; i < buflen; i++) {
    //    printf("%d",offsets_buffer[i]);
    //}
    //printf("\n");

    //printf("Matches: ");
    for (i = 0; i < buflen; i++) {
        if (host_offsets[i] == 0)
            continue;


        /* get our patterns from the hash */
        h = B2G_CUDA_HASH16(u8_tolower(buf[i + ctx->m - 2]),
                            u8_tolower(buf[i + ctx->m - 1]));

        if (ctx->bloom[h] != NULL) {
            COUNT(tctx->stat_pminlen_calls++);
            COUNT(tctx->stat_pminlen_total+=ctx->pminlen[h]);

            if ((buflen - i) < ctx->pminlen[h]) {
                continue;
            } else {
                COUNT(tctx->stat_bloom_calls++);

                if (BloomFilterTest(ctx->bloom[h], buf + i, ctx->pminlen[h]) == 0) {
                    COUNT(tctx->stat_bloom_hits++);

                    continue;
                }
            }
        }

        B2gCudaHashItem *hi = ctx->hash[h], *thi;
        for (thi = hi; thi != NULL; thi = thi->nxt) {
            COUNT(tctx->stat_d0_hashloop++);
            B2gCudaPattern *p = ctx->parray[thi->idx];

            if (p->flags & MPM_PATTERN_FLAG_NOCASE) {
                if ((buflen - i) < p->len) {
                    continue;
                }

                if (memcmp_lowercase(p->ci, buf + i, p->len) == 0) {
                    COUNT(tctx->stat_loop_match++);

                    matches += MpmVerifyMatch(mpm_thread_ctx, pmq, p->em, i, p->len);
                } else {
                    COUNT(tctx->stat_loop_no_match++);
                }
            } else {
                if (buflen - i < p->len)
                    continue;

                if (memcmp(p->cs, buf + i, p->len) == 0) {
                    COUNT(tctx->stat_loop_match++);

                    matches += MpmVerifyMatch(mpm_thread_ctx, pmq, p->em, i, p->len);
                } else {
                    COUNT(tctx->stat_loop_no_match++);
                }
            }
        }
    } /* for(i = 0; i < buflen; i++) */

    SCCudaMemFree(cuda_buf);
    SCCudaMemFree(cuda_offsets);

    return matches;

 error:
    if (cuda_buf != 0)
        SCCudaMemFree(cuda_buf);
    if (cuda_offsets != 0)
        SCCudaMemFree(cuda_offsets);
    return 0;
}

uint32_t B2gCudaSearch(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                       PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen)
{
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx->ctx;
#ifdef B2G_CUDA_COUNTERS
    B2gCudaThreadCtx *tctx = (B2gCudaThreadCtx *)mpm_thread_ctx->ctx;
#endif
    uint32_t pos = 0, matches = 0;
    B2G_CUDA_TYPE d;
    uint32_t j = 0;

    COUNT(tctx->stat_calls++);
    COUNT(tctx->stat_m_total+=ctx->m);

    if (buflen < ctx->m)
        return 0;

    while (pos <= (buflen - ctx->m)) {
        j = ctx->m - 1;
        d = ~0;

        do {
            uint16_t h = B2G_CUDA_HASH16(u8_tolower(buf[pos + j - 1]),
                                         u8_tolower(buf[pos + j]));
            d = ((d << 1) & ctx->B2G[h]);
            j = j - 1;
        } while (d != 0 && j != 0);

        /* (partial) match, move on to verification */
        if (d != 0) {
            COUNT(tctx->stat_d0++);

            /* get our patterns from the hash */
            uint16_t h = B2G_CUDA_HASH16(u8_tolower(buf[pos + ctx->m - 2]),
                                         u8_tolower(buf[pos + ctx->m - 1]));

            if (ctx->bloom[h] != NULL) {
                COUNT(tctx->stat_pminlen_calls++);
                COUNT(tctx->stat_pminlen_total+=ctx->pminlen[h]);

                if ((buflen - pos) < ctx->pminlen[h]) {
                    goto skip_loop;
                } else {
                    COUNT(tctx->stat_bloom_calls++);

                    if (BloomFilterTest(ctx->bloom[h], buf+pos, ctx->pminlen[h]) == 0) {
                        COUNT(tctx->stat_bloom_hits++);

                        goto skip_loop;
                    }
                }
            }

            B2gCudaHashItem *hi = ctx->hash[h];
            B2gCudaHashItem *thi = NULL;
            for (thi = hi; thi != NULL; thi = thi->nxt) {
                COUNT(tctx->stat_d0_hashloop++);
                B2gCudaPattern *p = ctx->parray[thi->idx];

                if (p->flags & MPM_PATTERN_FLAG_NOCASE) {
                    if (buflen - pos < p->len)
                        continue;

                    if (memcmp_lowercase(p->ci, buf+pos, p->len) == 0) {
                        COUNT(tctx->stat_loop_match++);

                        matches += MpmVerifyMatch(mpm_thread_ctx, pmq, p->em, pos, p->len);
                    } else {
                        COUNT(tctx->stat_loop_no_match++);
                    }
                } else {
                    if (buflen - pos < p->len)
                        continue;

                    if (memcmp(p->cs, buf+pos, p->len) == 0) {
                        COUNT(tctx->stat_loop_match++);

                        matches += MpmVerifyMatch(mpm_thread_ctx, pmq, p->em, pos, p->len);
                    } else {
                        COUNT(tctx->stat_loop_no_match++);
                    }
                }
            }
skip_loop:
            pos = pos + 1;
        } else {
            COUNT(tctx->stat_num_shift++);
            COUNT(tctx->stat_total_shift += (j + 1));

            pos = pos + j + 1;
        }
    }

    return matches;
}

#ifdef B2G_CUDA_SEARCH2
uint32_t B2gCudaSearch2(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                        PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen)
{
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx->ctx;
    uint8_t *bufmin = buf;
    uint8_t *bufend = buf + buflen - 1;
    uint32_t cnt = 0;
    B2gCudaPattern *p;
    MpmEndMatch *em;
    B2gCudaHashItem *thi, *hi;

    if (buflen < 2)
        return 0;

    while (buf <= bufend) {
        uint8_t h8 = u8_tolower(*buf);
        hi = &ctx->hash1[h8];

        if (hi->flags & 0x01) {
            for (thi = hi; thi != NULL; thi = thi->nxt) {
                p = ctx->parray[thi->idx];

                if (p->flags & MPM_PATTERN_FLAG_NOCASE) {
                    if (h8 == p->ci[0]) {
                        cnt += MpmVerifyMatch(mpm_thread_ctx, pmq, p->em, (buf+1 - bufmin), p->len);
                    }
                } else {
                    if (*buf == p->cs[0]) {
                        cnt += MpmVerifyMatch(mpm_thread_ctx, pmq, p->em, (buf+1 - bufmin), p->len);
                    }
                }
            }
        }

        /* save one conversion by reusing h8 */
        uint16_t h16 = B2G_HASH16(h8, u8_tolower(*(buf+1)));
        hi = ctx->hash2[h16];

        for (thi = hi; thi != NULL; thi = thi->nxt) {
            p = ctx->parray[thi->idx];

            if (p->flags & MPM_PATTERN_FLAG_NOCASE) {
                if (h8 == p->ci[0] && u8_tolower(*(buf+1)) == p->ci[1]) {
                    for (em = p->em; em; em = em->next) {
                        if (MpmVerifyMatch(mpm_thread_ctx, pmq, em, (buf+1 - bufmin), p->len))
                            cnt++;
                    }
                }
            } else {
                if (*buf == p->cs[0] && *(buf+1) == p->cs[1]) {
                    for (em = p->em; em; em = em->next) {
                        if (MpmVerifyMatch(mpm_thread_ctx, pmq, em, (buf+1 - bufmin), p->len))
                            cnt++;
                    }
                }
            }
        }
        buf += 1;
    }

    if (ctx->pat_x_cnt > 0) {
        /* Pass bufmin on because buf no longer points to the
         * start of the buffer. */
        cnt += ctx->MBSearch(mpm_ctx, mpm_thread_ctx, pmq, bufmin, buflen);
    }

    return cnt;
}
#endif

uint32_t B2gCudaSearch1(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                        PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen)
{
    SCEnter();

    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx->ctx;
    uint8_t *bufmin = buf;
    uint8_t *bufend = buf + buflen - 1;
    uint32_t cnt = 0;
    B2gCudaPattern *p;
    B2gCudaHashItem *thi, *hi;

    if (buflen == 0)
        SCReturnUInt(0);

    while (buf <= bufend) {
        uint8_t h = u8_tolower(*buf);
        hi = &ctx->hash1[h];

        if (hi->flags & 0x01) {
            for (thi = hi; thi != NULL; thi = thi->nxt) {
                p = ctx->parray[thi->idx];

                if (p->len != 1)
                    continue;

                if (p->flags & MPM_PATTERN_FLAG_NOCASE) {
                    if (u8_tolower(*buf) == p->ci[0]) {
                        cnt += MpmVerifyMatch(mpm_thread_ctx, pmq, p->em, (buf+1 - bufmin), p->len);
                    }
                } else {
                    if (*buf == p->cs[0]) {
                        cnt += MpmVerifyMatch(mpm_thread_ctx, pmq, p->em, (buf+1 - bufmin), p->len);
                    }
                }
            }
        }
        buf += 1;
    }

#ifdef B2G_CUDA_SEARCH2
    if (ctx->pat_2_cnt) {
        /* Pass bufmin on because buf no longer points to the
         * start of the buffer. */
        cnt += ctx->MBSearch2(mpm_ctx, mpm_thread_ctx, pmq, bufmin, buflen);
    } else
#endif
    if (ctx->pat_x_cnt) {
        cnt += ctx->MBSearch(mpm_ctx, mpm_thread_ctx, pmq, bufmin, buflen);
    }

    SCReturnUInt(cnt);
}

/*********************Cuda_Specific_Mgmt_Code_Starts_Here**********************/

/**
 * \brief The Cuda MPM B2G module's thread init function.
 *
 * \param tv       Pointer to the ThreadVars which has invoked this function.
 * \param initdata Pointer to some user sent data.
 * \param data     Pointer to a pointer which can be used to send data to the
 *                 dispatcher thread.
 *
 * \retval TM_ECODE_OK Always.
 */
TmEcode B2gCudaMpmDispThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCCudaHlModuleData *module_data = (SCCudaHlModuleData *)initdata;

    if (PatternMatchDefaultMatcher() != MPM_B2G_CUDA)
        return TM_ECODE_OK;

    if (SCCudaCtxPushCurrent(module_data->cuda_context) == -1) {
        SCLogError(SC_ERR_B2G_CUDA_ERROR, "Error pushing cuda context");
    }

    return TM_ECODE_OK;
}

/**
 * \brief The Cuda MPM B2G module's thread de-init function.
 *
 * \param tv   Pointer to the ThreadVars which has invoked this function.
 * \param data Pointer to the slot data if anything had been attached in
 *             the thread init function.
 *
 * \retval TM_ECODE_OK Always.
 */
TmEcode B2gCudaMpmDispThreadDeInit(ThreadVars *tv, void *data)
{
    if (PatternMatchDefaultMatcher() != MPM_B2G_CUDA)
        return TM_ECODE_OK;

    if (SCCudaCtxPopCurrent(NULL) == -1) {
        SCLogError(SC_ERR_B2G_CUDA_ERROR, "Error popping cuda context");
    }

    return TM_ECODE_OK;
}

/**
 * \brief The dispatcher function for the cuda mpm.  Takes a packet, feeds
 *        it to the gpu and informs the calling client when it has the
 *        results ready.
 *
 * \param tv   We don't need this.
 * \param p    Pointer to the Packet which contains all the relevant data,
 *             like the bufffer, buflen, the contexts.
 * \param data Pointer to the slot data if anything had been attached in
 *             the thread init function.
 * \param pq   We don't need this.
 *
 * \retval TM_ECODE_OK Always.
 */
TmEcode B2gCudaMpmDispatcher(ThreadVars *tv, Packet *p, void *data,
                             PacketQueue *pq)
{
    if (p == NULL)
        return TM_ECODE_OK;

    p->cuda_matches = mpm_table[p->cuda_mpm_ctx->mpm_type].Search(p->cuda_mpm_ctx,
                                                                  p->cuda_mtc,
                                                                  p->cuda_pmq,
                                                                  p->payload,
                                                                  p->payload_len);
    TmqhOutputSimpleOnQ(p->cuda_outq, p);

    return TM_ECODE_OK;
}

/**
 * \brief Registers the Cuda B2G MPM Module.
 */
void TmModuleCudaMpmB2gRegister(void)
{
    tmm_modules[TMM_CUDA_MPM_B2G].name = "Cuda_Mpm_B2g";
    tmm_modules[TMM_CUDA_MPM_B2G].ThreadInit = B2gCudaMpmDispThreadInit;
    tmm_modules[TMM_CUDA_MPM_B2G].Func = B2gCudaMpmDispatcher;
    tmm_modules[TMM_CUDA_MPM_B2G].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_CUDA_MPM_B2G].ThreadDeinit = B2gCudaMpmDispThreadDeInit;
    tmm_modules[TMM_CUDA_MPM_B2G].RegisterTests = NULL;
}

/***************************Code_Specific_To_Mpm_B2g***************************/

int B2gCudaStartDispatcherThreadRC(const char *name)
{
    SCCudaHlModuleData *data = NULL;
    TmModule *tm_module = NULL;

    if (name == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Error invalid arguments.  "
                   "name NULL");
        return -1;
    }

    if (tv_CMB2_RC != NULL) {
        SCLogError(SC_ERR_TM_THREADS_ERROR, "We already have this thread "
                   "running from b2g-cuda");
        return 0;
    }

    data = SCCudaHlGetModuleData(SCCudaHlGetModuleHandle(name));
    if (data == NULL) {
        SCLogDebug("Module not registered.  To avail the benefits of this "
                   "registration facility, first register a module using "
                   "context using SCCudaHlRegisterModule(), after which you "
                   "can call this function");
        return -1;
    }

    /* create the threads */
    tv_CMB2_RC = TmThreadCreatePacketHandler("Cuda_Mpm_B2g_RC",
                                             "rules_content_mpm_inqueue", "simple",
                                             NULL, NULL,
                                             "1slot_noout");
    if (tv_CMB2_RC == NULL) {
        SCLogError(SC_ERR_TM_THREADS_ERROR, "ERROR: TmThreadsCreate failed");
        exit(EXIT_FAILURE);
    }
    tv_CMB2_RC->inq->writer_cnt++;

    tm_module = TmModuleGetByName("Cuda_Mpm_B2g");
    if (tm_module == NULL) {
        SCLogError(SC_ERR_TM_MODULES_ERROR,
                   "ERROR: TmModuleGetByName failed for Cuda_Mpm_B2g_RC");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_CMB2_RC, tm_module, data);

    if (TmThreadSpawn(tv_CMB2_RC) != TM_ECODE_OK) {
        SCLogError(SC_ERR_TM_THREADS_ERROR, "ERROR: TmThreadSpawn failed");
        exit(EXIT_FAILURE);
    }

    TmThreadContinue(tv_CMB2_RC);

    return 0;
}

/**
 * \brief Hacks for the tests.  While running the tests, we sometimes need to
 *        kill the threads to make them pop the cuda contexts.  We don't need
 *        these under normal running.
 */
void B2gCudaKillDispatcherThreadRC(void)
{
    if (tv_CMB2_RC == NULL)
        return;

    TmThreadKillThread(tv_CMB2_RC);
    TmThreadRemove(tv_CMB2_RC, tv_CMB2_RC->type);
    SCFree(tv_CMB2_RC);
    tv_CMB2_RC = NULL;

    return;
}

void B2gCudaPushPacketTo_tv_CMB2_RC(Packet *p)
{
    PacketQueue *q = &trans_q[tv_CMB2_RC->inq->id];

    SCMutexLock(&q->mutex_q);
    PacketEnqueue(q, p);
    SCCondSignal(&q->cond_q);
    SCMutexUnlock(&q->mutex_q);

    return;
}

/*********************************Unittests************************************/

#ifdef UNITTESTS

static int B2gCudaTestInitTestEnv(void)
{
    SCCudaHlRegisterModule("B2G_CUDA_TEST");

    return 1;
}

static int B2gCudaTest01(void)
{
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    B2gCudaCtx *ctx = NULL;
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    B2gCudaInitCtx(&mpm_ctx, module_handle);

    ctx = mpm_ctx.ctx;

    if (ctx->cuda_context == 0)
        goto end;
    if (ctx->cuda_module == 0)
        goto end;
    if (ctx->cuda_search_kernel == 0)
        goto end;

    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"one", 3, 0, 0, 1, 1, 0) == -1)
        goto end;
    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"two", 3, 0, 0, 2, 1, 0) == -1)
        goto end;
    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"three", 5, 0, 0, 3, 1, 0) == -1)
        goto end;
    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"four", 4, 0, 0, 4, 1, 0) == -1)
        goto end;

    if (B2gCudaPreparePatterns(&mpm_ctx) == -1)
        goto end;
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 4 /* 4 patterns */);

    char *string = "onetwothreeaaaaoneaatwobbbthrbsonwehowvonwoonsldffoursadnothreewtowoneowtwo";
    result = (B2gCudaSearchBNDMq(&mpm_ctx, &mpm_thread_ctx, NULL,
                                 (uint8_t *)string, strlen(string)) == 9);

 end:
    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTest02(void)
{
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    B2gCudaCtx *ctx = NULL;
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    B2gCudaInitCtx(&mpm_ctx, module_handle);

    ctx = mpm_ctx.ctx;

    if (ctx->cuda_context == 0)
        goto end;
    if (ctx->cuda_module == 0)
        goto end;
    if (ctx->cuda_search_kernel == 0)
        goto end;

    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"one", 3, 0, 0, 1, 1, 0) == -1)
        goto end;
    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"two", 3, 0, 0, 2, 1, 0) == -1)
        goto end;
    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"three", 5, 0, 0, 3, 1, 0) == -1)
        goto end;
    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"four", 4, 0, 0, 4, 1, 0) == -1)
        goto end;

    if (B2gCudaPreparePatterns(&mpm_ctx) == -1)
        goto end;
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 4 /* 4 patterns */);

    char *string = "onetwothreeaaaaoneaatwobbbthrbsonwehowvonwoonsldffoursadnothreewtowoneowtwo";
    result = (B2gCudaSearchBNDMq(&mpm_ctx, &mpm_thread_ctx, NULL,
                                 (uint8_t *)string, strlen(string)) == 9);

 end:
    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

/**
 * \test Test that the *AddPattern* functions work as expected.
 */
static int B2gCudaTest03(void)
{
    MpmCtx mpm_ctx;
    B2gCudaCtx *ctx = NULL;
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    B2gCudaInitCtx(&mpm_ctx, module_handle);

    ctx = mpm_ctx.ctx;
    if (ctx->cuda_context == 0)
        goto end;
    if (ctx->cuda_module == 0)
        goto end;
    if (ctx->cuda_search_kernel == 0)
        goto end;

    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"onee", 4, 0, 0, 1, 1, 0) == -1)
        goto end;
    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"twoo", 4, 0, 0, 2, 1, 0) == -1)
        goto end;
    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"three", 5, 0, 0, 3, 1, 0) == -1)
        goto end;
    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"four", 4, 0, 0, 4, 1, 0) == -1)
        goto end;
    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"onee", 4, 0, 0, 1, 2, 0) == -1)
        goto end;

    if (B2gCudaPreparePatterns(&mpm_ctx) == -1)
        goto end;

    char *string = "one";
    result = (B2gCudaSearchBNDMq(&mpm_ctx, NULL, NULL, (uint8_t *)string, strlen(string)) == 0);

 end:
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

/**
 * \test Test that the *AddPattern* functions work as expected.
 */
static int B2gCudaTest04(void)
{
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    B2gCudaCtx *ctx = NULL;
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);

    ctx = mpm_ctx.ctx;
    if (ctx->cuda_context == 0)
        goto end;
    if (ctx->cuda_module == 0)
        goto end;
    if (ctx->cuda_search_kernel == 0)
        goto end;

    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"one", 3, 0, 0, 1, 1, 0) == -1)
        goto end;
    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"two", 3, 0, 0, 2, 1, 0) == -1)
        goto end;
    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"three", 5, 0, 0, 3, 1, 0) == -1)
        goto end;
    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"four", 4, 0, 0, 4, 1, 0) == -1)
        goto end;

    if (B2gCudaPreparePatterns(&mpm_ctx) == -1)
        goto end;
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 4 /* 4 patterns */);

    char *string = "onetwothreeaaaaoneaatwobbbthrbsonwehowvonwfouoonsldffoursadnothreewtowoneowtwo";
    result = (B2gCudaSearchBNDMq(&mpm_ctx, &mpm_thread_ctx,
                                 NULL, (uint8_t *)string, strlen(string)) == 9);

    result = 1;

 end:
    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestSearch01(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;
    char *buf = "abcdefghjiklmnopqrstuvwxyz";

    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);

    return result;
}

static int B2gCudaTestSearch02(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;
    char *buf = "abcdefghjiklmnopqrstuvwxyz";

    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abce", 4, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)buf, strlen(buf));

    if (cnt == 0)
        result = 1;

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);

    return result;
}

static int B2gCudaTestSearch03(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;
    char *buf = "abcdefghjiklmnopqrstuvwxyz";

    /* a match each for these strings */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"bcde", 4, 0, 0, 1, 0, 0);
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"fghj", 4, 0, 0, 2, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 3 /* 3 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)buf, strlen(buf));

    if (cnt == 3)
        result = 1;

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);

    return result;
}

/**
 * \test Test patterns longer than 'm'. M is 4 here.
 */
static int B2gCudaTestSearch04(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;
    char *buf = "abcdefghjiklmnopqrstuvwxyz";

    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"bcdegh", 6, 0, 0, 1, 0, 0);
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"fghjxyz", 7, 0, 0, 2, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 3 /* 3 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

/**
 * \test Case insensitive test patterns longer than 'm'. M is 4 here.
 */
static int B2gCudaTestSearch05(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;
    char *buf = "abcdefghjiklmnopqrstuvwxyz";

    B2gCudaAddPatternCI(&mpm_ctx, (uint8_t *)"ABCD", 4, 0, 0, 0, 0, 0);
    B2gCudaAddPatternCI(&mpm_ctx, (uint8_t *)"bCdEfG", 6, 0, 0, 1, 0, 0);
    B2gCudaAddPatternCI(&mpm_ctx, (uint8_t *)"fghJikl", 7, 0, 0, 2, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 3 /* 3 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)buf, strlen(buf));

    if (cnt == 3)
        result = 1;

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);

    return result;
}

static int B2gCudaTestSearch06(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;
    char *buf = "abcd";

    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);

    return result;
}

static int B2gCudaTestSearch07(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;
    char *buf = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    /* total matches: 135 */
    /* should match 30 times */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"A", 1, 0, 0, 0, 0, 0);
    /* should match 29 times */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 1, 0, 0);
    /* should match 28 times */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"AAA", 3, 0, 0, 2, 0, 0);
    /* should match 26 times */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAA", 5, 0, 0, 3, 0, 0);
    /* should match 21 times */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAAAAAAA", 10, 0, 0, 4, 0, 0);
    /* should match 1 time */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 30, 0, 0, 5, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 6 /* 6 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)buf, strlen(buf));


    if (cnt == 135)
        result = 1;

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);

    return result;
}

static int B2gCudaTestSearch08(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0); /* 1 match */

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"a", 1);

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

/* we segfault with this test */
static int B2gCudaTestSearch09(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"ab", 2, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"ab", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestSearch10(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abcdefgh", 8, 0, 0, 0, 0, 0); /* 1 match */

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    char *buf = "01234567890123456789012345678901234567890123456789"
                "01234567890123456789012345678901234567890123456789"
                "abcdefgh"
                "01234567890123456789012345678901234567890123456789"
                "01234567890123456789012345678901234567890123456789";
    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestSearch11(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abcde", 5, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 2 /* 2 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL,
                             (uint8_t *)"abcdefghijklmnopqrstuvwxyz", 26);

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestSearch12(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"wxyz", 4, 0, 0, 0, 0, 0); /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"vwxyz", 5, 0, 0, 0, 0, 0); /* 1 match */

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 2 /* 2 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL,
                             (uint8_t *)"abcdefghijklmnopqrstuvwxyz", 26);

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestSearch13(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abcdefghijklmnopqrstuvwxyzABCD",
                            30, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL,
                             (uint8_t *)"abcdefghijklmnopqrstuvwxyzABCD", 30);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestSearch14(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abcdefghijklmnopqrstuvwxyzABCDE",
                            31, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL,
                             (uint8_t *)"abcdefghijklmnopqrstuvwxyzABCDE", 31);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestSearch15(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abcdefghijklmnopqrstuvwxyzABCDEF",
                            32, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL,
                             (uint8_t *)"abcdefghijklmnopqrstuvwxyzABCDEF", 32);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestSearch16(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abcdefghijklmnopqrstuvwxyzABC",
                            29, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL,
                             (uint8_t *)"abcdefghijklmnopqrstuvwxyzABC", 29);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestSearch17(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abcdefghijklmnopqrstuvwxyzAB",
                            28, 0, 0, 0, 0, 0); /* 1 match */

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL,
                             (uint8_t *)"abcdefghijklmnopqrstuvwxyzAB", 28);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestSearch18(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx,
                            (uint8_t *)"abcde""fghij""klmno""pqrst""uvwxy""z",
                            26, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL,
                             (uint8_t *)"abcde""fghij""klmno""pqrst""uvwxy""z",
                             26);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestSearch19(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                            30, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL,
                             (uint8_t *)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 30);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestSearch20(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 */
    B2gCudaAddPatternCS(&mpm_ctx,
                            (uint8_t *)"AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AA",
                            32, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL,
                             (uint8_t *)"AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AA",
                             32);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestSearch21(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"AA", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}



static int B2gCudaTestSearch22(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL,
                               (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestSearch23(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abce", 4, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL,
                               (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestSearch24(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"bcde", 4, 0, 0, 1, 0, 0);
    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"fghj", 4, 0, 0, 2, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 3 /* 3 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL,
                               (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

/**
 * \test test patterns longer than 'm'. M is 4 here.
 */
static int B2gCudaTestSearch25(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"bcdegh", 6, 0, 0, 1, 0, 0);
    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"fghjxyz", 7, 0, 0, 2, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 3 /* 3 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL,
                               (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

/**
 * \test case insensitive test patterns longer than 'm'. M is 4 here.
 */
static int B2gCudaTestSearch26(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 match */
    B2gCudaAddPatternCI(&mpm_ctx, (uint8_t *)"ABCD", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    B2gCudaAddPatternCI(&mpm_ctx, (uint8_t *)"bCdEfG", 6, 0, 0, 1, 0, 0);
    /* 1 match */
    B2gCudaAddPatternCI(&mpm_ctx, (uint8_t *)"fghJikl", 7, 0, 0, 2, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 3 /* 3 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL,
                               (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestSearch27(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcd", 4);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestSearch28(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* should match 30 times */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"A", 1, 0, 0, 0, 0, 0);
    /* should match 29 times */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 1, 0, 0);
    /* should match 28 times */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"AAA", 3, 0, 0, 2, 0, 0);
    /* 26 */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAA", 5, 0, 0, 3, 0, 0);
    /* 21 */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAAAAAAA", 10, 0, 0, 4, 0, 0);
    /* 1 */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        30, 0, 0, 5, 0, 0);
    /* total matches: 135 */

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 6 /* 6 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL,
                               (uint8_t *)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 30);

    if (cnt == 135)
        result = 1;
    else
        printf("135 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestSearch29(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"a", 1);

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestSearch30(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"ab", 2, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"ab", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

/* 1 match */
static int B2gCudaTestSearch31(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abcdefgh", 8, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    char *buf = "01234567890123456789012345678901234567890123456789"
                "01234567890123456789012345678901234567890123456789"
                "abcdefgh"
                "01234567890123456789012345678901234567890123456789"
                "01234567890123456789012345678901234567890123456789";
    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)buf,
                               strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestSearch32(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abcde", 5, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 2 /* 2 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL,
                               (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestSearch33(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"wxyz", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"vwxyz", 5, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 2 /* 2 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL,
                               (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestDeInitTestEnv(void)
{
    CUcontext context;
    if (SCCudaCtxPopCurrent(&context) == -1)
        exit(EXIT_FAILURE);
    SCCudaHlDeRegisterModule("B2G_CUDA_TEST");

    return 1;
}

#endif /* UNITTESTS */

/*********************************Unittests************************************/

void B2gCudaRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("B2gCudaTestInitTestEnv", B2gCudaTestInitTestEnv, 1);
    UtRegisterTest("B2gCudaTest01", B2gCudaTest01, 1);
    UtRegisterTest("B2gCudaTest02", B2gCudaTest02, 1);
    UtRegisterTest("B2gCudaTest03", B2gCudaTest03, 1);
    UtRegisterTest("B2gCudaTest04", B2gCudaTest04, 1);
    UtRegisterTest("B2gCudaTestSearch01", B2gCudaTestSearch01, 1);
    UtRegisterTest("B2gCudaTestSearch02", B2gCudaTestSearch02, 1);
    UtRegisterTest("B2gCudaTestSearch03", B2gCudaTestSearch03, 1);
    UtRegisterTest("B2gCudaTestSearch04", B2gCudaTestSearch04, 1);
    UtRegisterTest("B2gCudaTestSearch05", B2gCudaTestSearch05, 1);
    UtRegisterTest("B2gCudaTestSearch06", B2gCudaTestSearch06, 1);
    UtRegisterTest("B2gCudaTestSearch07", B2gCudaTestSearch07, 1);
    UtRegisterTest("B2gCudaTestSearch08", B2gCudaTestSearch08, 1);
    UtRegisterTest("B2gCudaTestSearch09", B2gCudaTestSearch09, 1);
    UtRegisterTest("B2gCudaTestSearch10", B2gCudaTestSearch10, 1);
    UtRegisterTest("B2gCudaTestSearch11", B2gCudaTestSearch11, 1);
    UtRegisterTest("B2gCudaTestSearch12", B2gCudaTestSearch12, 1);
    UtRegisterTest("B2gCudaTestSearch13", B2gCudaTestSearch13, 1);

    UtRegisterTest("B2gCudaTestSearch14", B2gCudaTestSearch14, 1);
    UtRegisterTest("B2gCudaTestSearch15", B2gCudaTestSearch15, 1);
    UtRegisterTest("B2gCudaTestSearch16", B2gCudaTestSearch16, 1);
    UtRegisterTest("B2gCudaTestSearch17", B2gCudaTestSearch17, 1);
    UtRegisterTest("B2gCudaTestSearch18", B2gCudaTestSearch18, 1);
    UtRegisterTest("B2gCudaTestSearch19", B2gCudaTestSearch19, 1);
    UtRegisterTest("B2gCudaTestSearch20", B2gCudaTestSearch20, 1);
    UtRegisterTest("B2gCudaTestSearch21", B2gCudaTestSearch21, 1);

    UtRegisterTest("B2gCudaTestSearch22", B2gCudaTestSearch22, 1);
    UtRegisterTest("B2gCudaTestSearch23", B2gCudaTestSearch23, 1);
    UtRegisterTest("B2gCudaTestSearch24", B2gCudaTestSearch24, 1);
    UtRegisterTest("B2gCudaTestSearch25", B2gCudaTestSearch25, 1);
    UtRegisterTest("B2gCudaTestSearch26", B2gCudaTestSearch26, 1);
    UtRegisterTest("B2gCudaTestSearch27", B2gCudaTestSearch27, 1);
    UtRegisterTest("B2gCudaTestSearch28", B2gCudaTestSearch28, 1);
    UtRegisterTest("B2gCudaTestSearch29", B2gCudaTestSearch29, 1);
    UtRegisterTest("B2gCudaTestSearch30", B2gCudaTestSearch30, 1);
    UtRegisterTest("B2gCudaTestSearch31", B2gCudaTestSearch31, 1);
    UtRegisterTest("B2gCudaTestSearch32", B2gCudaTestSearch32, 1);
    UtRegisterTest("B2gCudaTestSearch33", B2gCudaTestSearch33, 1);
    /* we actually need to call this.  right now we don't need this.  we will
     * change this in the next patch for cuda batching */
    UtRegisterTest("B2gCudaTestDeInitTestEnv", B2gCudaTestDeInitTestEnv, 1);
#endif /* UNITTESTS */
}

#endif /* __SC_CUDA_SUPPORT */
