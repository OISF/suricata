/**
 * Copyright (c) 2009 Open Information Security Foundation.
 *
 * \author Victor Julien <victor@inliniac.net>
 * \author Anoop Saldanha <poonaatsoc@gmail.com>
 *
 * \todo Lot of work on the kernel pending.  Includes handling kernel block
 *       handling, optimization with shared memory, blah blah blah....  We
 *       will come back to that once we have the cuda framework in place.
 */

#include "suricata-common.h"
#include "suricata.h"
#include "detect.h"
#include "util-bloomfilter.h"
#include "util-mpm-b2g-cuda.h"
#include "util-mpm.h"
#include "util-print.h"
#include "threadvars.h"
#include "tm-modules.h"

#include "util-error.h"
#include "util-debug.h"
#include "util-unittest.h"

#include "app-layer-detect-proto.h"
#include "util-cuda-handlers.h"
#include "util-cuda.h"
#include "tm-threads.h"
#include "threads.h"

/* macros decides if cuda is enabled for the platform or not */
#ifdef __SC_CUDA_SUPPORT__

#define INIT_HASH_SIZE 65536

#ifdef B2G_CUDA_COUNTERS
#define COUNT(counter) (counter)
#else
#define COUNT(counter)
#endif /* B2G_CUDA_COUNTERS */

/* threadvars Cuda(C) Mpm(M) B2G(B) Rules(R) Content(C) */
ThreadVars *tv_CMB2_RC = NULL;

/* threadvars Cuda(C) Mpm(M) B2G(B) App(A) Proto(P) Content(C) */
ThreadVars *tv_CMB2_APC = NULL;

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
int B2gCudaAddScanPatternCI(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t,
                            uint32_t, uint32_t, uint8_t);
int B2gCudaAddScanPatternCS(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t,
                            uint32_t, uint32_t, uint8_t);
int B2gCudaAddPatternCI(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                        uint16_t offset, uint16_t depth, uint32_t pid,
                        uint32_t sid);
int B2gCudaAddPatternCS(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                        uint16_t offset, uint16_t depth, uint32_t pid,
                        uint32_t sid);
int B2gCudaPreparePatterns(MpmCtx *mpm_ctx);
inline uint32_t B2gCudaScanWrap(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                                PatternMatcherQueue *, uint8_t *buf,
                                uint16_t buflen);
inline uint32_t B2gCudaSearchWrap(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                                  PatternMatcherQueue *, uint8_t *buf,
                                  uint16_t buflen);
uint32_t B2gCudaScan1(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                      PatternMatcherQueue *, uint8_t *buf, uint16_t buflen);

#ifdef B2G_SCAN2
uint32_t B2gCudaScan2(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                      PatternMatcherQueue *, uint8_t *buf, uint16_t buflen);
#endif

uint32_t B2gCudaScan(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                     PatternMatcherQueue *, uint8_t *buf, uint16_t buflen);
uint32_t B2gCudaScanBNDMq(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                          PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen);
uint32_t B2gCudaSearch1(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                        PatternMatcherQueue *, uint8_t *buf, uint16_t buflen);
uint32_t B2gCudaSearchBNDMq(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                            PatternMatcherQueue *pmq, uint8_t *buf,
                            uint16_t buflen);
uint32_t B2gCudaSearch(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                       PatternMatcherQueue *, uint8_t *buf, uint16_t buflen);
void B2gCudaPrintInfo(MpmCtx *mpm_ctx);
void B2gCudaPrintSearchStats(MpmThreadCtx *mpm_thread_ctx);
void B2gCudaRegisterTests(void);

/* for debugging purposes.  keep it for now */
int arg0 = 0;
int arg1 = 0;
int arg2 = 0;
int arg3 = 0;
int arg4 = 0;
int arg5 = 0;
int arg_total = 0;

/**
 * \todo Optimize the kernel.  Also explore the options for compiling the
 *       *.cu file at compile/runtime.
 */
const char *b2g_cuda_ptx_image =
    "    .version 1.4\n"
    "	.target sm_10, map_f64_to_f32\n"
    "	.entry B2gCudaSearchBNDMq (\n"
    "		.param .u32 __cudaparm_B2gCudaSearchBNDMq_offsets,\n"
    "		.param .u32 __cudaparm_B2gCudaSearchBNDMq_search_B2G,\n"
    "		.param .u32 __cudaparm_B2gCudaSearchBNDMq_g_u8_lowercasetable,\n"
    "		.param .u32 __cudaparm_B2gCudaSearchBNDMq_buf,\n"
    "		.param .u16 __cudaparm_B2gCudaSearchBNDMq_arg_buflen,\n"
    "		.param .u32 __cudaparm_B2gCudaSearchBNDMq_search_m)\n"
    "	{\n"
    "	.reg .u32 %r<81>;\n"
    "	.reg .pred %p<14>;\n"
    "	.loc	15	14	0\n"
    "$LBB1_B2gCudaSearchBNDMq:\n"
    "	.loc	15	16	0\n"
    "	ld.param.u32 	%r1, [__cudaparm_B2gCudaSearchBNDMq_search_m];\n"
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
    "	ld.param.u32 	%r37, [__cudaparm_B2gCudaSearchBNDMq_search_B2G];\n"
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
    "\n"
    "	.entry B2gCudaScanBNDMq (\n"
    "		.param .u32 __cudaparm_B2gCudaScanBNDMq_offsets,\n"
    "		.param .u32 __cudaparm_B2gCudaScanBNDMq_scan_B2G,\n"
    "		.param .u32 __cudaparm_B2gCudaScanBNDMq_g_u8_lowercasetable,\n"
    "		.param .u32 __cudaparm_B2gCudaScanBNDMq_buf,\n"
    "		.param .u16 __cudaparm_B2gCudaScanBNDMq_arg_buflen,\n"
    "		.param .u32 __cudaparm_B2gCudaScanBNDMq_scan_m)\n"
    "	{\n"
    "	.reg .u32 %r<81>;\n"
    "	.reg .pred %p<14>;\n"
    "	.loc	15	80	0\n"
    "$LBB1_B2gCudaScanBNDMq:\n"
    "	.loc	15	82	0\n"
    "	ld.param.u32 	%r1, [__cudaparm_B2gCudaScanBNDMq_scan_m];\n"
    "	sub.u32 	%r2, %r1, 1;\n"
    "	mov.s32 	%r3, %r2;\n"
    "	.loc	15	88	0\n"
    "	ld.param.u16 	%r4, [__cudaparm_B2gCudaScanBNDMq_arg_buflen];\n"
    "	shr.u32 	%r5, %r4, 4;\n"
    "	cvt.u16.u32 	%r6, %r5;\n"
    "	mov.s32 	%r7, %r6;\n"
    "	setp.ge.u32 	%p1, %r6, %r1;\n"
    "	@%p1 bra 	$Lt_1_8450;\n"
    "	.loc	15	93	0\n"
    "	cvt.u16.u32 	%r7, %r1;\n"
    "$Lt_1_8450:\n"
    "	cvt.u32.u16 	%r8, %tid.x;\n"
    "	mul.lo.u32 	%r9, %r7, %r8;\n"
    "	cvt.u16.u32 	%r10, %r9;\n"
    "	add.s32 	%r11, %r7, %r10;\n"
    "	setp.ge.s32 	%p2, %r4, %r11;\n"
    "	@%p2 bra 	$Lt_1_8962;\n"
    "	bra.uni 	$LBB23_B2gCudaScanBNDMq;\n"
    "$Lt_1_8962:\n"
    "	.loc	15	99	0\n"
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
    "	@%p3 bra 	$Lt_1_9474;\n"
    "	.loc	15	101	0\n"
    "	sub.u32 	%r25, %r4, %r9;\n"
    "	cvt.u16.u32 	%r16, %r25;\n"
    "$Lt_1_9474:\n"
    "	mov.u32 	%r26, 0;\n"
    "	setp.eq.u32 	%p4, %r16, %r26;\n"
    "	@%p4 bra 	$Lt_1_9986;\n"
    "	mov.s32 	%r27, %r16;\n"
    "	ld.param.u32 	%r28, [__cudaparm_B2gCudaScanBNDMq_offsets];\n"
    "	mov.u32 	%r29, 0;\n"
    "	mov.s32 	%r30, %r27;\n"
    "$Lt_1_10498:\n"
    " //<loop> Loop body line 101, nesting depth: 1, estimated iterations: unknown\n"
    "	.loc	15	106	0\n"
    "	mov.u32 	%r31, 0;\n"
    "	add.u32 	%r32, %r10, %r29;\n"
    "	mul.lo.u32 	%r33, %r32, 4;\n"
    "	add.u32 	%r34, %r28, %r33;\n"
    "	st.global.u32 	[%r34+0], %r31;\n"
    "	add.u32 	%r29, %r29, 1;\n"
    "	setp.ne.u32 	%p5, %r16, %r29;\n"
    "	@%p5 bra 	$Lt_1_10498;\n"
    "$Lt_1_9986:\n"
    "	sub.u32 	%r35, %r16, 1;\n"
    "	setp.gt.u32 	%p6, %r2, %r35;\n"
    "	@%p6 bra 	$LBB23_B2gCudaScanBNDMq;\n"
    "	ld.param.u32 	%r36, [__cudaparm_B2gCudaScanBNDMq_g_u8_lowercasetable];\n"
    "	ld.param.u32 	%r37, [__cudaparm_B2gCudaScanBNDMq_scan_B2G];\n"
    "	ld.param.u32 	%r38, [__cudaparm_B2gCudaScanBNDMq_buf];\n"
    "$Lt_1_11522:\n"
    " //<loop> Loop body line 112\n"
    "	.loc	15	112	0\n"
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
    "	@%p7 bra 	$Lt_1_258;\n"
    " //<loop> Part of loop body line 112, head labeled $Lt_1_11522\n"
    "	.loc	15	115	0\n"
    "	mov.s32 	%r29, %r3;\n"
    "	.loc	15	116	0\n"
    "	sub.u32 	%r53, %r3, %r1;\n"
    "	add.u32 	%r54, %r53, 1;\n"
    "	sub.s32 	%r55, %r1, 1;\n"
    "$Lt_1_12546:\n"
    " //<loop> Loop body line 119\n"
    "	.loc	15	119	0\n"
    "	sub.u32 	%r29, %r29, 1;\n"
    "	shr.u32 	%r56, %r51, %r55;\n"
    "	mov.u32 	%r57, 0;\n"
    "	setp.eq.u32 	%p8, %r56, %r57;\n"
    "	@%p8 bra 	$Lt_1_13314;\n"
    " //<loop> Part of loop body line 119, head labeled $Lt_1_12546\n"
    "	setp.ge.u32 	%p9, %r54, %r29;\n"
    "	@%p9 bra 	$Lt_1_13570;\n"
    " //<loop> Part of loop body line 119, head labeled $Lt_1_12546\n"
    "	.loc	15	122	0\n"
    "	mov.s32 	%r3, %r29;\n"
    "	bra.uni 	$Lt_1_13314;\n"
    "$Lt_1_13570:\n"
    " //<loop> Part of loop body line 119, head labeled $Lt_1_12546\n"
    "	.loc	15	124	0\n"
    "	mov.u32 	%r58, 1;\n"
    "	ld.param.u32 	%r59, [__cudaparm_B2gCudaScanBNDMq_offsets];\n"
    "	add.u32 	%r60, %r10, %r29;\n"
    "	mul.lo.u32 	%r61, %r60, 4;\n"
    "	add.u32 	%r62, %r59, %r61;\n"
    "	st.global.u32 	[%r62+0], %r58;\n"
    "$Lt_1_13314:\n"
    "$Lt_1_12802:\n"
    " //<loop> Part of loop body line 119, head labeled $Lt_1_12546\n"
    "	.loc	15	129	0\n"
    "	mov.u32 	%r63, 0;\n"
    "	setp.eq.u32 	%p10, %r29, %r63;\n"
    "	@%p10 bra 	$Lt_1_258;\n"
    " //<loop> Part of loop body line 119, head labeled $Lt_1_12546\n"
    "	.loc	15	132	0\n"
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
    "	@%p11 bra 	$Lt_1_12546;\n"
    "$Lt_1_258:\n"
    "$Lt_1_11778:\n"
    " //<loop> Part of loop body line 112, head labeled $Lt_1_11522\n"
    "	.loc	15	135	0\n"
    "	add.u32 	%r79, %r3, %r1;\n"
    "	sub.u32 	%r3, %r79, 1;\n"
    "	setp.ge.u32 	%p12, %r35, %r3;\n"
    "	@%p12 bra 	$Lt_1_11522;\n"
    "$LBB23_B2gCudaScanBNDMq:\n"
    "	.loc	15	138	0\n"
    "	exit;\n"
    "$LDWend_B2gCudaScanBNDMq:\n"
    "	} // B2gCudaScanBNDMq\n"
    "\n";

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
    mpm_table[MPM_B2G_CUDA].AddScanPattern = B2gCudaAddScanPatternCS;
    mpm_table[MPM_B2G_CUDA].AddScanPatternNocase = B2gCudaAddScanPatternCI;
    mpm_table[MPM_B2G_CUDA].AddPattern = B2gCudaAddPatternCS;
    mpm_table[MPM_B2G_CUDA].AddPatternNocase = B2gCudaAddPatternCI;
    mpm_table[MPM_B2G_CUDA].Prepare = B2gCudaPreparePatterns;
    mpm_table[MPM_B2G_CUDA].Scan = B2gCudaScanWrap;
    mpm_table[MPM_B2G_CUDA].Search = B2gCudaSearchWrap;
    mpm_table[MPM_B2G_CUDA].Cleanup = MpmMatchCleanup;
    mpm_table[MPM_B2G_CUDA].PrintCtx = B2gCudaPrintInfo;
    mpm_table[MPM_B2G_CUDA].PrintThreadCtx = B2gCudaPrintSearchStats;
    mpm_table[MPM_B2G_CUDA].RegisterUnittests = B2gCudaRegisterTests;
}

static inline void B2gCudaEndMatchAppend(MpmCtx *mpm_ctx, B2gCudaPattern *p,
                                         uint16_t offset, uint16_t depth,
                                         uint32_t pid, uint32_t sid,
                                         uint8_t nosearch)
{
    MpmEndMatch *em = MpmAllocEndMatch(mpm_ctx);
    if (em == NULL) {
        SCLogDebug("ERROR: B2gAllocEndMatch failed");
        return;
    }

    SCLogDebug("em alloced at %p", em);

    em->id = pid;
    em->sig_id = sid;
    em->depth = depth;
    em->offset = offset;

    if (nosearch)
        em->flags |= MPM_ENDMATCH_NOSEARCH;

    if (p->em == NULL) {
        p->em = em;
        SCLogDebug("m %p m->sig_id %"PRIu32"", em, em->sig_id);
        return;
    }

    MpmEndMatch *m = p->em;
    while (m->next)
        m = m->next;
    m->next = em;

    m = p->em;
    SCLogDebug("m %p m->sig_id %" PRIu32, m, m->sig_id);
    while (m->next) {
        m = m->next;
        SCLogDebug("m %p m->sig_id %" PRIu32, m, m->sig_id);
    }

    return;
}

void B2gCudaPrintInfo(MpmCtx *mpm_ctx)
{
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx->ctx;

    SCLogDebug("MPM B2g Cuda Information:");
    SCLogDebug("Memory allocs:   %" PRIu32, mpm_ctx->memory_cnt);
    SCLogDebug("Memory alloced:  %" PRIu32, mpm_ctx->memory_size);
    SCLogDebug(" Sizeofs:");
    SCLogDebug("  MpmCtx         %" PRIuMAX, (uintmax_t)sizeof(MpmCtx));
    SCLogDebug("  B2gCuda        %" PRIuMAX, (uintmax_t)sizeof(B2gCudaCtx));
    SCLogDebug("  B2gCudaPattern %" PRIuMAX, (uintmax_t)sizeof(B2gCudaPattern));
    SCLogDebug("  B2gCudaHashIte %" PRIuMAX, (uintmax_t)sizeof(B2gCudaHashItem));
    SCLogDebug("Unique Patterns: %" PRIu32, mpm_ctx->pattern_cnt);
    SCLogDebug("Scan Patterns:   %" PRIu32, mpm_ctx->scan_pattern_cnt);
    SCLogDebug("Total Patterns:  %" PRIu32, mpm_ctx->total_pattern_cnt);
    SCLogDebug("Smallest:        %" PRIu32, mpm_ctx->scan_minlen);
    SCLogDebug("Largest:         %" PRIu32, mpm_ctx->scan_maxlen);
    SCLogDebug("Hash size:       %" PRIu32, ctx->scan_hash_size);

    return;
}

static inline B2gCudaPattern *B2gCudaAllocPattern(MpmCtx *mpm_ctx)
{
    B2gCudaPattern *p = malloc(sizeof(B2gCudaPattern));
    if (p == NULL) {
        printf("ERROR: B2gAllocPattern: malloc failed\n");
        exit(EXIT_FAILURE);
    }
    memset(p, 0, sizeof(B2gCudaPattern));

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(B2gCudaPattern);

    return p;
}

static inline B2gCudaHashItem *B2gCudaAllocHashItem(MpmCtx *mpm_ctx)
{
    B2gCudaHashItem *hi = malloc(sizeof(B2gCudaHashItem));
    if (hi == NULL) {
        printf("ERROR: B2gCudaAllocHashItem: malloc failed\n");
        exit(EXIT_FAILURE);
    }
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
    free(hi);

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
                                    uint16_t patlen, char nocase);

static inline B2gCudaPattern *B2gCudaInitHashLookup(B2gCudaCtx *ctx, uint8_t *pat,
                                                    uint16_t patlen, char nocase)
{
    uint32_t hash = B2gCudaInitHashRaw(pat, patlen);

    if (ctx->init_hash[hash] == NULL)
        return NULL;

    B2gCudaPattern *t = ctx->init_hash[hash];
    for ( ; t != NULL; t = t->next) {
        if (B2gCudaCmpPattern(t, pat, patlen, nocase) == 1)
            return t;
    }

    return NULL;
}

static inline int B2gCudaCmpPattern(B2gCudaPattern *p, uint8_t *pat,
                                    uint16_t patlen, char nocase)
{
    if (p->len != patlen)
        return 0;

    if (!((nocase && p->flags & B2G_CUDA_NOCASE) ||
          (!nocase && !(p->flags & B2G_CUDA_NOCASE)))) {
        return 0;
    }

    if (memcmp(p->cs, pat, patlen) != 0)
        return 0;

    return 1;
}

void B2gCudaFreePattern(MpmCtx *mpm_ctx, B2gCudaPattern *p)
{
    if (p && p->em)
        MpmEndMatchFreeAll(mpm_ctx, p->em);

    if (p && p->cs && p->cs != p->ci) {
        free(p->cs);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= p->len;
    }

    if (p && p->ci) {
        free(p->ci);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= p->len;
    }

    if (p) {
        free(p);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= sizeof(B2gCudaPattern);
    }

    return;
}

static inline int B2gCudaAddPattern(MpmCtx *mpm_ctx, uint8_t *pat,
                                    uint16_t patlen, uint16_t offset,
                                    uint16_t depth, char nocase, char scan,
                                    uint32_t pid, uint32_t sid,
                                    uint8_t nosearch)
{
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx->ctx;

    SCLogDebug("ctx %p len %"PRIu16" pid %" PRIu32 ", nocase %s",
               ctx, patlen, pid, nocase ? "true" : "false");

    if (patlen == 0)
        return 0;

    /* get a memory piece */
    B2gCudaPattern *p = B2gCudaInitHashLookup(ctx, pat, patlen, nocase);
    if (p == NULL) {
        SCLogDebug("allocing new pattern");

        p = B2gCudaAllocPattern(mpm_ctx);
        if (p == NULL)
            goto error;

        p->len = patlen;

        if (nocase)
            p->flags |= B2G_CUDA_NOCASE;

        /* setup the case insensitive part of the pattern */
        p->ci = malloc(patlen);
        if (p->ci == NULL)
            goto error;
        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size += patlen;
        memcpy_tolower(p->ci, pat, patlen);

        /* setup the case sensitive part of the pattern */
        if (p->flags & B2G_CUDA_NOCASE) {
            /* nocase means no difference between cs and ci */
            p->cs = p->ci;
        } else {
            if (memcmp(p->ci,pat,p->len) == 0) {
                /* no diff between cs and ci: pat is lowercase */
                p->cs = p->ci;
            } else {
                p->cs = malloc(patlen);
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
            exit(1);
        }
        if (scan)
            mpm_ctx->scan_pattern_cnt++;
        mpm_ctx->pattern_cnt++;

        if (scan) { /* SCAN */
            if (mpm_ctx->scan_maxlen < patlen)
                mpm_ctx->scan_maxlen = patlen;

            if (mpm_ctx->scan_minlen == 0)
                mpm_ctx->scan_minlen = patlen;
            else if (mpm_ctx->scan_minlen > patlen)
                mpm_ctx->scan_minlen = patlen;

            p->flags |= B2G_CUDA_SCAN;
        } else { /* SEARCH */
            if (mpm_ctx->search_maxlen < patlen)
                mpm_ctx->search_maxlen = patlen;

            if (mpm_ctx->search_minlen == 0)
                mpm_ctx->search_minlen = patlen;
            else if (mpm_ctx->search_minlen > patlen)
                mpm_ctx->search_minlen = patlen;
        }
    } else {
        /* if we're reusing a pattern, check we need to check that it is a
         * scan pattern if that is what we're adding. If so we set the pattern
         * to be a scan pattern. */
        if (scan) {
            p->flags |= B2G_CUDA_SCAN;

            if (mpm_ctx->scan_maxlen < patlen)
                mpm_ctx->scan_maxlen = patlen;

            if (mpm_ctx->scan_minlen == 0)
                mpm_ctx->scan_minlen = patlen;
            else if (mpm_ctx->scan_minlen > patlen)
                mpm_ctx->scan_minlen = patlen;
        }
    }

    /* we need a match */
    B2gCudaEndMatchAppend(mpm_ctx, p, offset, depth, pid, sid, nosearch);

    mpm_ctx->total_pattern_cnt++;

    return 0;

error:
    B2gCudaFreePattern(mpm_ctx, p);
    return -1;
}

int B2gCudaAddScanPatternCI(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                            uint16_t offset, uint16_t depth, uint32_t pid,
                            uint32_t sid, uint8_t nosearch)
{
    return B2gCudaAddPattern(mpm_ctx, pat, patlen, offset, depth, /* nocase */1,
                             /* scan */1, pid, sid, nosearch);
}

int B2gCudaAddScanPatternCS(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                            uint16_t offset, uint16_t depth, uint32_t pid,
                            uint32_t sid, uint8_t nosearch)
{
    return B2gCudaAddPattern(mpm_ctx, pat, patlen, offset, depth, /* nocase */0,
                             /* scan */1, pid, sid, nosearch);
}

int B2gCudaAddPatternCI(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                        uint16_t offset, uint16_t depth, uint32_t pid,
                        uint32_t sid)
{
    return B2gCudaAddPattern(mpm_ctx, pat, patlen, offset, depth, /* nocase */1,
                             /* scan */0, pid, sid, 0);
}

int B2gCudaAddPatternCS(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
                        uint16_t offset, uint16_t depth, uint32_t pid,
                        uint32_t sid)
{
    return B2gCudaAddPattern(mpm_ctx, pat, patlen, offset, depth, /* nocase */0,
                             /* scan */0, pid, sid, 0);
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

static void B2gCudaPrepareScanHash(MpmCtx *mpm_ctx)
{
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx->ctx;
    uint16_t i;
    uint16_t idx = 0;
    uint8_t idx8 = 0;

    ctx->scan_hash = (B2gCudaHashItem **)malloc(sizeof(B2gCudaHashItem *) *
                                                ctx->scan_hash_size);
    if (ctx->scan_hash == NULL)
        goto error;
    memset(ctx->scan_hash, 0, sizeof(B2gCudaHashItem *) * ctx->scan_hash_size);

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (sizeof(B2gCudaHashItem *) * ctx->scan_hash_size);

#ifdef B2G_CUDA_SCAN2
    ctx->scan_hash2 = (B2gCudaHashItem **)malloc(sizeof(B2gCudaHashItem *) *
                                                 ctx->scan_hash_size);
    if (ctx->scan_hash2 == NULL)
        goto error;
    memset(ctx->scan_hash2, 0, sizeof(B2gCudaHashItem *) * ctx->scan_hash_size);

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (sizeof(B2gCudaHashItem *) * ctx->scan_hash_size);
#endif

    /* alloc the pminlen array */
    ctx->scan_pminlen = (uint8_t *)malloc(sizeof(uint8_t) * ctx->scan_hash_size);
    if (ctx->scan_pminlen == NULL)
        goto error;
    memset(ctx->scan_pminlen, 0, sizeof(uint8_t) * ctx->scan_hash_size);

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (sizeof(uint8_t) * ctx->scan_hash_size);

    for (i = 0; i < mpm_ctx->pattern_cnt; i++)
    {
        /* ignore patterns that don't have the scan flag set */
        if (!(ctx->parray[i]->flags & B2G_CUDA_SCAN))
            continue;

        if (ctx->parray[i]->len == 1) {
            idx8 = (uint8_t)ctx->parray[i]->ci[0];
            if (ctx->scan_hash1[idx8].flags == 0) {
                ctx->scan_hash1[idx8].idx = i;
                ctx->scan_hash1[idx8].flags |= 0x01;
            } else {
                B2gCudaHashItem *hi = B2gCudaAllocHashItem(mpm_ctx);
                hi->idx = i;
                hi->flags |= 0x01;

                /* Append this HashItem to the list */
                B2gCudaHashItem *thi = &ctx->scan_hash1[idx8];
                while (thi->nxt) thi = thi->nxt;
                thi->nxt = hi;
            }
            ctx->scan_1_pat_cnt++;
#ifdef B2G_CUDA_SCAN2
        } else if(ctx->parray[i]->len == 2) {
            idx = B2G_CUDA_HASH16(ctx->parray[i]->ci[0], ctx->parray[i]->ci[1]);
            if (ctx->scan_hash2[idx] == NULL) {
                B2gCudaHashItem *hi = B2gCudaAllocHashItem(mpm_ctx);
                hi->idx = i;
                hi->flags |= 0x01;

                ctx->scan_hash2[idx] = hi;
            } else {
                B2gCudaHashItem *hi = B2gCudaAllocHashItem(mpm_ctx);
                hi->idx = i;
                hi->flags |= 0x01;

                /* Append this HashItem to the list */
                B2gCudaHashItem *thi = ctx->scan_hash2[idx];
                while (thi->nxt) thi = thi->nxt;
                thi->nxt = hi;
            }
            ctx->scan_2_pat_cnt++;
#endif
        } else {
            idx = B2G_CUDA_HASH16(ctx->parray[i]->ci[ctx->scan_m - 2],
                                  ctx->parray[i]->ci[ctx->scan_m - 1]);
            SCLogDebug("idx %" PRIu32 ", %c.%c", idx,
                       ctx->parray[i]->ci[ctx->scan_m - 2],
                       ctx->parray[i]->ci[ctx->scan_m - 1]);

            if (ctx->scan_hash[idx] == NULL) {
                B2gCudaHashItem *hi = B2gCudaAllocHashItem(mpm_ctx);
                hi->idx = i;
                hi->flags |= 0x01;
                ctx->scan_pminlen[idx] = ctx->parray[i]->len;

                ctx->scan_hash[idx] = hi;
            } else {
                B2gCudaHashItem *hi = B2gCudaAllocHashItem(mpm_ctx);
                hi->idx = i;
                hi->flags |= 0x01;

                if (ctx->parray[i]->len < ctx->scan_pminlen[idx])
                    ctx->scan_pminlen[idx] = ctx->parray[i]->len;

                /* Append this HashItem to the list */
                B2gCudaHashItem *thi = ctx->scan_hash[idx];
                while (thi->nxt) thi = thi->nxt;
                thi->nxt = hi;
            }
            ctx->scan_x_pat_cnt++;
        }
    }

    /* alloc the bloom array */
    ctx->scan_bloom = (BloomFilter **)malloc(sizeof(BloomFilter *) * ctx->scan_hash_size);
    if (ctx->scan_bloom == NULL) goto error;
    memset(ctx->scan_bloom, 0, sizeof(BloomFilter *) * ctx->scan_hash_size);

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (sizeof(BloomFilter *) * ctx->scan_hash_size);

    uint32_t h;
    for (h = 0; h < ctx->scan_hash_size; h++) {
        B2gCudaHashItem *hi = ctx->scan_hash[h];
        if (hi == NULL)
            continue;

        ctx->scan_bloom[h] = BloomFilterInit(B2G_CUDA_BLOOMSIZE, 2,
                                             B2gCudaBloomHash);
        if (ctx->scan_bloom[h] == NULL)
            continue;

        mpm_ctx->memory_cnt += BloomFilterMemoryCnt(ctx->scan_bloom[h]);
        mpm_ctx->memory_size += BloomFilterMemorySize(ctx->scan_bloom[h]);

        if (ctx->scan_pminlen[h] > 8)
            ctx->scan_pminlen[h] = 8;

        B2gCudaHashItem *thi = hi;
        do {
            SCLogDebug("adding \"%c%c\" to the bloom",
                       ctx->parray[thi->idx]->ci[0],
                       ctx->parray[thi->idx]->ci[1]);
            BloomFilterAdd(ctx->scan_bloom[h], ctx->parray[thi->idx]->ci,
                           ctx->scan_pminlen[h]);
            thi = thi->nxt;
        } while (thi != NULL);
    }

    return;
error:
    return;
}

static void B2gCudaPrepareSearchHash(MpmCtx *mpm_ctx)
{
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx->ctx;
    uint16_t i;
    uint16_t idx = 0;
    uint8_t idx8 = 0;

    ctx->search_hash = (B2gCudaHashItem **)malloc(sizeof(B2gCudaHashItem *) *
                                                  ctx->search_hash_size);
    if (ctx->search_hash == NULL) goto error;
    memset(ctx->search_hash, 0, sizeof(B2gCudaHashItem *) * ctx->search_hash_size);

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (sizeof(B2gCudaHashItem *) * ctx->search_hash_size);

    /* alloc the pminlen array */
    ctx->search_pminlen = (uint8_t *)malloc(sizeof(uint8_t) * ctx->search_hash_size);
    if (ctx->search_pminlen == NULL)
        goto error;
    memset(ctx->search_pminlen, 0, sizeof(uint8_t) * ctx->search_hash_size);

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (sizeof(uint8_t) * ctx->search_hash_size);

    for (i = 0; i < mpm_ctx->pattern_cnt; i++)
    {
        /* ignore patterns that have the scan flag set */
        if (ctx->parray[i]->flags & B2G_CUDA_SCAN)
            continue;

        if(ctx->parray[i]->len == 1) {
            idx8 = (uint8_t)ctx->parray[i]->ci[0];
            if (ctx->search_hash1[idx8].flags == 0) {
                ctx->search_hash1[idx8].idx = i;
                ctx->search_hash1[idx8].flags |= 0x01;
            } else {
                B2gCudaHashItem *hi = B2gCudaAllocHashItem(mpm_ctx);
                hi->idx = i;
                hi->flags |= 0x01;

                /* Append this HashItem to the list */
                B2gCudaHashItem *thi = &ctx->search_hash1[idx8];
                while (thi->nxt)
                    thi = thi->nxt;
                thi->nxt = hi;
            }
        } else {
            idx = B2G_CUDA_HASH16(ctx->parray[i]->ci[ctx->search_m - 2],
                                  ctx->parray[i]->ci[ctx->search_m - 1]);

            if (ctx->search_hash[idx] == NULL) {
                B2gCudaHashItem *hi = B2gCudaAllocHashItem(mpm_ctx);
                hi->idx = i;
                hi->flags |= 0x01;
                ctx->search_pminlen[idx] = ctx->parray[i]->len;

                ctx->search_hash[idx] = hi;
            } else {
                B2gCudaHashItem *hi = B2gCudaAllocHashItem(mpm_ctx);
                hi->idx = i;
                hi->flags |= 0x01;

                if (ctx->parray[i]->len < ctx->search_pminlen[idx])
                    ctx->search_pminlen[idx] = ctx->parray[i]->len;

                /* Append this HashItem to the list */
                B2gCudaHashItem *thi = ctx->search_hash[idx];
                while (thi->nxt)
                    thi = thi->nxt;
                thi->nxt = hi;
            }
        }
    }

    /* alloc the bloom array */
    ctx->search_bloom = (BloomFilter **)malloc(sizeof(BloomFilter *) * ctx->search_hash_size);
    if (ctx->search_bloom == NULL)
        goto error;
    memset(ctx->search_bloom, 0, sizeof(BloomFilter *) * ctx->search_hash_size);

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (sizeof(BloomFilter *) * ctx->search_hash_size);

    uint32_t h;
    for (h = 0; h < ctx->search_hash_size; h++) {
        B2gCudaHashItem *hi = ctx->search_hash[h];
        if (hi == NULL)
            continue;

        ctx->search_bloom[h] = BloomFilterInit(B2G_CUDA_BLOOMSIZE, 2, B2gCudaBloomHash);
        if (ctx->search_bloom[h] == NULL)
            continue;

        mpm_ctx->memory_cnt += BloomFilterMemoryCnt(ctx->search_bloom[h]);
        mpm_ctx->memory_size += BloomFilterMemorySize(ctx->search_bloom[h]);

        if (ctx->search_pminlen[h] > 8)
            ctx->search_pminlen[h] = 8;

        B2gCudaHashItem *thi = hi;
        do {
            BloomFilterAdd(ctx->search_bloom[h], ctx->parray[thi->idx]->ci, ctx->search_pminlen[h]);
            thi = thi->nxt;
        } while (thi != NULL);
    }
    return;

error:
    return;
}

int B2gCudaBuildScanMatchArray(MpmCtx *mpm_ctx)
{
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx->ctx;

    ctx->scan_B2G = malloc(sizeof(B2G_CUDA_TYPE) * ctx->scan_hash_size);
    if (ctx->scan_B2G == NULL)
        return -1;

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (sizeof(B2G_CUDA_TYPE) * ctx->scan_hash_size);

    memset(ctx->scan_B2G,0, B2G_CUDA_HASHSIZE * sizeof(B2G_CUDA_TYPE));

    uint32_t j;
    uint32_t a;

    /* fill the match array */
    for (j = 0; j <= (ctx->scan_m - B2G_CUDA_Q); j++) {
        for (a = 0; a < mpm_ctx->pattern_cnt; a++) {
            if (!(ctx->parray[a]->flags & B2G_CUDA_SCAN))
                continue;

            if (ctx->parray[a]->len < ctx->scan_m)
                continue;

            uint16_t h = B2G_CUDA_HASH16(u8_tolower(ctx->parray[a]->ci[j]),
                                         u8_tolower(ctx->parray[a]->ci[j+1]));
            ctx->scan_B2G[h] = ctx->scan_B2G[h] | (1 << (ctx->scan_m - j));

            SCLogDebug("h %"PRIu16", ctx->scan_B2G[h] %" PRIu32 "", h,
                       ctx->scan_B2G[h]);
        }
    }

    ctx->scan_s0 = 1;

    return 0;
}

int B2gCudaBuildSearchMatchArray(MpmCtx *mpm_ctx)
{
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx->ctx;

    ctx->search_B2G = malloc(sizeof(B2G_CUDA_TYPE) * ctx->search_hash_size);
    if (ctx->search_B2G == NULL)
        return -1;

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (sizeof(B2G_CUDA_TYPE) * ctx->search_hash_size);

    memset(ctx->search_B2G,0, B2G_CUDA_HASHSIZE * sizeof(B2G_CUDA_TYPE));

    uint32_t j;
    uint32_t a;

    /* fill the match array */
    for (j = 0; j <= (ctx->search_m - B2G_CUDA_Q); j++) {
        for (a = 0; a < mpm_ctx->pattern_cnt; a++) {
            if (ctx->parray[a]->flags & B2G_CUDA_SCAN)
                continue;

            if (ctx->parray[a]->len < ctx->search_m)
                continue;

            uint16_t h = B2G_CUDA_HASH16(u8_tolower(ctx->parray[a]->ci[j]),
                                         u8_tolower(ctx->parray[a]->ci[j+1]));

            ctx->search_B2G[h] = ctx->search_B2G[h] | (1 << (ctx->search_m - j));
        }
    }

    return 0;
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
    if (SCCudaMemAlloc(&ctx->cuda_search_B2G,
                       sizeof(B2G_CUDA_TYPE) * ctx->search_hash_size) == -1) {
        goto error;
    }
    if (SCCudaMemcpyHtoD(ctx->cuda_search_B2G, ctx->search_B2G,
                         sizeof(B2G_CUDA_TYPE) * ctx->search_hash_size) == -1) {
        goto error;
    }

    /* scan kernel */
    if (SCCudaMemAlloc(&ctx->cuda_scan_B2G,
                       sizeof(B2G_CUDA_TYPE) * ctx->scan_hash_size) == -1) {
        goto error;
    }
    if (SCCudaMemcpyHtoD(ctx->cuda_scan_B2G, ctx->scan_B2G,
                         sizeof(B2G_CUDA_TYPE) * ctx->scan_hash_size) == -1) {
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
    if (SCCudaParamSetv(ctx->cuda_search_kernel, B2G_CUDA_KERNEL_ARG2_OFFSET,
                        (void *)&ctx->cuda_g_u8_lowercasetable,
                        sizeof(void *)) == -1) {
        goto error;
    }

    /* scan kernel */
    if (SCCudaParamSetv(ctx->cuda_scan_kernel, B2G_CUDA_KERNEL_ARG1_OFFSET,
                        (void *)&ctx->cuda_scan_B2G, sizeof(void *)) == -1) {
        goto error;
    }

    if (SCCudaParamSetv(ctx->cuda_scan_kernel, B2G_CUDA_KERNEL_ARG2_OFFSET,
                        (void *)&ctx->cuda_g_u8_lowercasetable,
                        sizeof(void *)) == -1) {
        goto error;
    }

    if (SCCudaParamSeti(ctx->cuda_scan_kernel, B2G_CUDA_KERNEL_ARG5_OFFSET,
                        ctx->scan_m) == -1) {
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
    ctx->parray = (B2gCudaPattern **)malloc(mpm_ctx->pattern_cnt *
                                            sizeof(B2gCudaPattern *));
    if (ctx->parray == NULL)
        goto error;
    memset(ctx->parray, 0, mpm_ctx->pattern_cnt * sizeof(B2gCudaPattern *));

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (mpm_ctx->pattern_cnt * sizeof(B2gCudaPattern *));

    /* populate it with the patterns in the hash */
    uint32_t i = 0, p = 0;
    for (i = 0; i < INIT_HASH_SIZE; i++) {
        B2gCudaPattern *node = ctx->init_hash[i], *nnode = NULL;
        for ( ; node != NULL; ) {
            nnode = node->next;
            node->next = NULL;

            ctx->parray[p] = node;

            p++;
            node = nnode;
        }
    }
    /* we no longer need the hash, so free it's memory */
    free(ctx->init_hash);
    ctx->init_hash = NULL;

    /* set 'm' to the smallest pattern size */
    ctx->scan_m = mpm_ctx->scan_minlen;
    ctx->search_m = mpm_ctx->search_minlen;

    if (mpm_ctx->search_minlen == 1) {
        ctx->Search = B2gCudaSearch1;
        ctx->MBSearch = B2G_CUDA_SEARCHFUNC;
    }
    /* make sure 'm' stays in bounds
       m can be max WORD_SIZE - 1 */
    if (ctx->scan_m >= B2G_CUDA_WORD_SIZE) {
        ctx->scan_m = B2G_CUDA_WORD_SIZE - 1;
    }
    if (ctx->scan_m < 2)
        ctx->scan_m = 2;

    if (ctx->search_m >= B2G_CUDA_WORD_SIZE) {
        ctx->search_m = B2G_CUDA_WORD_SIZE - 1;
    }
    if (ctx->search_m < 2)
        ctx->search_m = 2;

    ctx->scan_hash_size = B2G_CUDA_HASHSIZE;
    ctx->search_hash_size = B2G_CUDA_HASHSIZE;
    B2gCudaPrepareScanHash(mpm_ctx);
    B2gCudaPrepareSearchHash(mpm_ctx);
    B2gCudaBuildScanMatchArray(mpm_ctx);
    B2gCudaBuildSearchMatchArray(mpm_ctx);

    if (B2gCudaSetDeviceBuffers(mpm_ctx) == -1)
        goto error;

    if (B2gCudaSetKernelArgs(mpm_ctx) == -1)
        goto error;

    SCLogDebug("ctx->scan_1_pat_cnt %"PRIu16"", ctx->scan_1_pat_cnt);
    if (ctx->scan_1_pat_cnt) {
        ctx->Scan = B2gCudaScan1;
#ifdef B2G_CUDA_SCAN2
        ctx->Scan = B2gCudaScan2;
        if (ctx->scan_2_pat_cnt) {
            ctx->MBScan2 = B2gCudaScan2;
        }
#endif
        ctx->MBScan = B2G_CUDA_SCANFUNC;
#ifdef B2G_SCAN2
    } else if (ctx->scan_2_pat_cnt) {
        ctx->Scan = B2gCudaScan2;
        ctx->MBScan = B2G_CUDA_SCANFUNC;
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

    printf("B2gCuda Thread Search stats (tctx %p)\n", tctx);
    printf("Scan phase:\n");
    printf("Total calls/scans: %" PRIu32 "\n", tctx->scan_stat_calls);
    printf("Avg m/scan: %0.2f\n", (tctx->scan_stat_calls ?
                                   ((float)tctx->scan_stat_m_total /
                                    (float)tctx->scan_stat_calls)) : 0);
    printf("D != 0 (possible match): %" PRIu32 "\n", tctx->scan_stat_d0);
    printf("Avg hash items per bucket %0.2f (%" PRIu32 ")\n",
           (tctx->scan_stat_d0 ? ((float)tctx->scan_stat_d0_hashloop /
                                  (float)tctx->scan_stat_d0)) : 0,
           tctx->scan_stat_d0_hashloop);
    printf("Loop match: %" PRIu32 "\n", tctx->scan_stat_loop_match);
    printf("Loop no match: %" PRIu32 "\n", tctx->scan_stat_loop_no_match);
    printf("Num shifts: %" PRIu32 "\n", tctx->scan_stat_num_shift);
    printf("Total shifts: %" PRIu32 "\n", tctx->scan_stat_total_shift);
    printf("Avg shifts: %0.2f\n", (tctx->scan_stat_num_shift ?
                                   ((float)tctx->scan_stat_total_shift /
                                    (float)tctx->scan_stat_num_shift)) : 0);
    printf("Total BloomFilter checks: %" PRIu32 "\n", tctx->scan_stat_bloom_calls);
    printf("BloomFilter hits: %0.4f%% (%" PRIu32 ")\n",
           (tctx->scan_stat_bloom_calls ?
            ((float)tctx->scan_stat_bloom_hits /
             (float)tctx->scan_stat_bloom_calls) * (float)100) : 0,
           tctx->scan_stat_bloom_hits);
    printf("Avg pminlen: %0.2f\n\n", (tctx->scan_stat_pminlen_calls ?
                                      ((float)tctx->scan_stat_pminlen_total /
                                       (float)tctx->scan_stat_pminlen_calls)) : 0);
    printf("Search phase:\n");
    printf("D 0 (possible match, shift = 1): %" PRIu32 "\n", tctx->search_stat_d0);
    printf("Loop match: %" PRIu32 "\n", tctx->search_stat_loop_match);
    printf("Loop no match: %" PRIu32 "\n", tctx->search_stat_loop_no_match);
    printf("Num shifts: %" PRIu32 "\n", tctx->search_stat_num_shift);
    printf("Total shifts: %" PRIu32 "\n", tctx->search_stat_total_shift);
    printf("Avg shifts: %0.2f\n\n", (tctx->search_stat_num_shift ?
                                     ((float)tctx->search_stat_total_shift /
                                      (float)tctx->search_stat_num_shift)) : 0);
#endif /* B2G_CUDA_COUNTERS */

    return;
}

static inline int memcmp_lowercase(uint8_t *s1, uint8_t *s2, uint16_t n)
{
    size_t i;

    /* check backwards because we already tested the first
     * 2 to 4 chars. This way we are more likely to detect
     * a miss and thus speed up a little... */
    for (i = n - 1; i; i--) {
        if (u8_tolower(*(s2+i)) != s1[i])
            return 1;
    }

    return 0;
}

void B2gCudaInitCtx(MpmCtx *mpm_ctx, int module_handle)
{
    SCLogDebug("mpm_ctx %p, ctx %p", mpm_ctx, mpm_ctx->ctx);

    BUG_ON(mpm_ctx->ctx != NULL);

    mpm_ctx->ctx = malloc(sizeof(B2gCudaCtx));
    if (mpm_ctx->ctx == NULL)
        return;

    memset(mpm_ctx->ctx, 0, sizeof(B2gCudaCtx));

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(B2gCudaCtx);

    /* initialize the hash we use to speed up pattern insertions */
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx->ctx;
    ctx->init_hash = malloc(sizeof(B2gCudaPattern *) * INIT_HASH_SIZE);
    if (ctx->init_hash == NULL)
        return;

    memset(ctx->init_hash, 0, sizeof(B2gCudaPattern *) * INIT_HASH_SIZE);

    /* init defaults */
    ctx->Scan = B2G_CUDA_SCANFUNC;
    ctx->Search = B2G_CUDA_SEARCHFUNC;

    ctx->module_handle = module_handle;

    if (SCCudaHlGetCudaContext(&ctx->cuda_context, module_handle) == -1) {
        SCLogError(SC_ERR_B2G_CUDA_ERROR, "Error getting a cuda context");
    }

    if (SCCudaHlGetCudaModule(&ctx->cuda_module, b2g_cuda_ptx_image,
                              module_handle) == -1) {
        SCLogError(SC_ERR_B2G_CUDA_ERROR, "Error getting a cuda module");
    }

    if (SCCudaModuleGetFunction(&ctx->cuda_search_kernel, ctx->cuda_module,
                                B2G_CUDA_SEARCHFUNC_NAME) == -1) {
        SCLogError(SC_ERR_B2G_CUDA_ERROR, "Error getting a cuda function");
    }

    if (SCCudaModuleGetFunction(&ctx->cuda_scan_kernel, ctx->cuda_module,
                                B2G_CUDA_SCANFUNC_NAME) == -1) {
        SCLogError(SC_ERR_B2G_CUDA_ERROR, "Error getting a cuda function");
    }

    /* we will need this for debugging purposes.  keep it here now */
//#define ALIGN_UP(offset, alignment)
//    (offset) = ((offset) + (alignment) - 1) & ~((alignment) - 1)
//
//    int offset = 0;
//
//    ALIGN_UP(offset, __alignof(void *));
//    arg0 = offset;
//    offset += sizeof(void *);
//
//    ALIGN_UP(offset, __alignof(void *));
//    arg1 = offset;
//    offset += sizeof(void *);
//
//    ALIGN_UP(offset, __alignof(void *));
//    arg2 = offset;
//    offset += sizeof(void *);
//
//    ALIGN_UP(offset, __alignof(void *));
//    arg3 = offset;
//    offset += sizeof(void *);
//
//    ALIGN_UP(offset, __alignof(unsigned short));
//    arg4 = offset;
//    offset += sizeof(unsigned short);
//
//    ALIGN_UP(offset, __alignof(unsigned int));
//    arg5 = offset;
//    offset += sizeof(unsigned int);
//
//    printf("arg0: %d\n", arg0);
//    printf("arg1: %d\n", arg1);
//    printf("arg2: %d\n", arg2);
//    printf("arg3: %d\n", arg3);
//    printf("arg4: %d\n", arg4);
//    printf("arg5: %d\n", arg5);
//
//    arg_total = offset;
//
//    printf("arg_total: %d\n", arg_total);

    return;
}

void B2gCudaDestroyCtx(MpmCtx *mpm_ctx)
{
    SCLogDebug("mpm_ctx %p", mpm_ctx);

    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx->ctx;
    if (ctx == NULL)
        return;

    if (ctx->init_hash) {
        free(ctx->init_hash);
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

        free(ctx->parray);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (mpm_ctx->pattern_cnt * sizeof(B2gCudaPattern));
    }

    if (ctx->scan_B2G) {
        free(ctx->scan_B2G);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (sizeof(B2G_CUDA_TYPE) * ctx->scan_hash_size);
    }

    if (ctx->search_B2G) {
        free(ctx->search_B2G);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (sizeof(B2G_CUDA_TYPE) * ctx->search_hash_size);
    }

    if (ctx->scan_bloom) {
        uint32_t h;
        for (h = 0; h < ctx->scan_hash_size; h++) {
            if (ctx->scan_bloom[h] == NULL)
                continue;

            mpm_ctx->memory_cnt -= BloomFilterMemoryCnt(ctx->scan_bloom[h]);
            mpm_ctx->memory_size -= BloomFilterMemorySize(ctx->scan_bloom[h]);

            BloomFilterFree(ctx->scan_bloom[h]);
        }

        free(ctx->scan_bloom);

        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (sizeof(BloomFilter *) * ctx->scan_hash_size);
    }

    if (ctx->scan_hash) {
        uint32_t h;
        for (h = 0; h < ctx->scan_hash_size; h++) {
            if (ctx->scan_hash[h] == NULL)
                continue;

            B2gCudaHashFree(mpm_ctx, ctx->scan_hash[h]);
        }

        free(ctx->scan_hash);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (sizeof(B2gCudaHashItem) * ctx->scan_hash_size);
    }

    if (ctx->search_bloom) {
        uint32_t h;
        for (h = 0; h < ctx->search_hash_size; h++) {
            if (ctx->search_bloom[h] == NULL)
                continue;

            mpm_ctx->memory_cnt -= BloomFilterMemoryCnt(ctx->search_bloom[h]);
            mpm_ctx->memory_size -= BloomFilterMemorySize(ctx->search_bloom[h]);

            BloomFilterFree(ctx->search_bloom[h]);
        }

        free(ctx->search_bloom);

        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (sizeof(BloomFilter *) * ctx->search_hash_size);
    }

    if (ctx->search_hash) {
        uint32_t h;
        for (h = 0; h < ctx->search_hash_size; h++) {
            if (ctx->search_hash[h] == NULL)
                continue;

            B2gCudaHashFree(mpm_ctx, ctx->search_hash[h]);
        }

        free(ctx->search_hash);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (sizeof(B2gCudaHashItem) * ctx->search_hash_size);
    }

    if (ctx->scan_pminlen) {
        free(ctx->scan_pminlen);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (sizeof(uint8_t) * ctx->scan_hash_size);
    }

    if (ctx->search_pminlen) {
        free(ctx->search_pminlen);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (sizeof(uint8_t) * ctx->search_hash_size);
    }

    if (ctx->cuda_search_B2G != 0) {
        if (SCCudaMemFree(ctx->cuda_search_B2G) == -1)
            SCLogError(SC_ERR_B2G_CUDA_ERROR, "Error freeing ctx->cuda_search_B2G ");
        ctx->cuda_search_B2G = 0;
    }

    if (ctx->cuda_scan_B2G != 0) {
        if (SCCudaMemFree(ctx->cuda_scan_B2G) == -1)
            SCLogError(SC_ERR_B2G_CUDA_ERROR, "Error freeing ctx->cuda_scan_B2G ");
        ctx->cuda_scan_B2G = 0;
    }

    free(mpm_ctx->ctx);
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
        mpm_thread_ctx->ctx = malloc(sizeof(B2gCudaThreadCtx));
        if (mpm_thread_ctx->ctx == NULL)
            return;

        memset(mpm_thread_ctx->ctx, 0, sizeof(B2gCudaThreadCtx));

        mpm_thread_ctx->memory_cnt++;
        mpm_thread_ctx->memory_size += sizeof(B2gCudaThreadCtx);
    }

    /* alloc an array with the size of _all_ keys in all instances.
     * this is done so the detect engine won't have to care about
     * what instance it's looking up in. The matches all have a
     * unique id and is the array lookup key at the same time */
    uint32_t keys = matchsize + 1;
    if (keys > 0) {
        mpm_thread_ctx->match = malloc(keys * sizeof(MpmMatchBucket));
        if (mpm_thread_ctx->match == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Could not setup memory for "
                       "pattern matcher: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }
        memset(mpm_thread_ctx->match, 0, keys * sizeof(MpmMatchBucket));

        mpm_thread_ctx->memory_cnt++;
        mpm_thread_ctx->memory_size += (keys * sizeof(MpmMatchBucket));
    }

    mpm_thread_ctx->matchsize = matchsize;

    return;
}

void B2gCudaThreadDestroyCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx)
{
    B2gCudaThreadCtx *ctx = (B2gCudaThreadCtx *)mpm_thread_ctx->ctx;

    B2gCudaPrintSearchStats(mpm_thread_ctx);

    /* can be NULL if B2gCudaThreadCtx is optimized to 0 */
    if (ctx != NULL) {
        mpm_thread_ctx->memory_cnt--;
        mpm_thread_ctx->memory_size -= sizeof(B2gCudaThreadCtx);
        free(mpm_thread_ctx->ctx);
    }

    if (mpm_thread_ctx->match != NULL) {
        mpm_thread_ctx->memory_cnt--;
        mpm_thread_ctx->memory_size -= ((mpm_thread_ctx->matchsize + 1) *
                                        sizeof(MpmMatchBucket));
        free(mpm_thread_ctx->match);
    }

    MpmMatchFreeSpares(mpm_thread_ctx, mpm_thread_ctx->sparelist);
    MpmMatchFreeSpares(mpm_thread_ctx, mpm_thread_ctx->qlist);

    return;
}

inline uint32_t B2gCudaScanWrap(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                                PatternMatcherQueue *pmq, uint8_t *buf,
                                uint16_t buflen)
{
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx->ctx;
    return ctx ? ctx->Scan(mpm_ctx, mpm_thread_ctx, pmq, buf, buflen) : 0;
}

inline uint32_t B2gCudaSearchWrap(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                                  PatternMatcherQueue *pmq, uint8_t *buf,
                                  uint16_t buflen)
{
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx->ctx;
    return ctx ? ctx->Search(mpm_ctx, mpm_thread_ctx, pmq, buf, buflen) : 0;
}

uint32_t B2gCudaScanBNDMq(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
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

    if (buflen < ctx->search_m)
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

    if (SCCudaParamSetv(ctx->cuda_scan_kernel, B2G_CUDA_KERNEL_ARG0_OFFSET,
                        (void *)&cuda_offsets, sizeof(void *)) == -1) {
        goto error;
    }

    if (SCCudaParamSetv(ctx->cuda_scan_kernel, B2G_CUDA_KERNEL_ARG1_OFFSET,
                        (void *)&ctx->cuda_scan_B2G, sizeof(void *)) == -1) {
        goto error;
    }

    if (SCCudaParamSetv(ctx->cuda_scan_kernel, B2G_CUDA_KERNEL_ARG3_OFFSET,
                        (void *)&cuda_buf, sizeof(void *)) == -1) {
        goto error;
    }

    if (SCCudaParamSeti(ctx->cuda_scan_kernel, B2G_CUDA_KERNEL_ARG4_OFFSET,
                        buflen) == -1) {
        goto error;
    }

    if (SCCudaParamSeti(ctx->cuda_scan_kernel, B2G_CUDA_KERNEL_ARG5_OFFSET,
                        ctx->scan_m) == -1) {
        goto error;
    }

    if (SCCudaParamSetSize(ctx->cuda_scan_kernel, B2G_CUDA_KERNEL_TOTAL_ARG_SIZE) == -1)
        goto error;

    if (SCCudaFuncSetBlockShape(ctx->cuda_scan_kernel, CUDA_THREADS, 1, 1) == -1)
        goto error;

    if (SCCudaLaunchGrid(ctx->cuda_scan_kernel, 1, 1) == -1)
        goto error;

    if (SCCudaMemcpyDtoH(host_offsets, cuda_offsets, buflen * sizeof(int)) == -1)
        goto error;

    //printf("Raw matches: ");
    //for (i = 0; i < buflen; i++) {
    //    printf("%d",offsets_buffer[i]);
    //}
    //printf("\n");

    //printf("Scan Matches: ");
    for (i = 0; i < buflen; i++) {
        if (host_offsets[i] == 0)
            continue;
        //printf("%d ", i);

        /* get our patterns from the hash */
        h = B2G_CUDA_HASH16(u8_tolower(buf[i + ctx->scan_m - 2]),
                            u8_tolower(buf[i + ctx->scan_m - 1]));

        if (ctx->scan_bloom[h] != NULL) {
            COUNT(tctx->scan_stat_pminlen_calls++);
            COUNT(tctx->scan_stat_pminlen_total+=ctx->scan_pminlen[h]);

            if ((buflen - i) < ctx->scan_pminlen[h]) {
                continue;
            } else {
                COUNT(tctx->scan_stat_bloom_calls++);

                if (BloomFilterTest(ctx->scan_bloom[h], buf+i,
                                    ctx->scan_pminlen[h]) == 0) {
                    COUNT(tctx->scan_stat_bloom_hits++);

                    continue;
                }
            }
        }

        B2gCudaHashItem *hi = ctx->scan_hash[h], *thi;
        for (thi = hi; thi != NULL; thi = thi->nxt) {
            COUNT(tctx->scan_stat_d0_hashloop++);
            B2gCudaPattern *p = ctx->parray[thi->idx];

            if (p->flags & B2G_CUDA_NOCASE) {
                if ((buflen - i) < p->len)
                    continue;

                if (memcmp_lowercase(p->ci, buf+i, p->len) == 0) {
                    COUNT(tctx->scan_stat_loop_match++);

                    MpmEndMatch *em;
                    for (em = p->em; em; em = em->next) {
                        SCLogDebug("em %p id %" PRIu32 "", em, em->id);
                        if (MpmMatchAppend(mpm_thread_ctx, pmq, em,
                                           &mpm_thread_ctx->match[em->id],
                                           i, p->len))
                            matches++;
                    }
                } else {
                    COUNT(tctx->scan_stat_loop_no_match++);
                }
            } else {
                if (buflen - i < p->len)
                    continue;

                if (memcmp(p->cs, buf+i, p->len) == 0) {
                    COUNT(tctx->scan_stat_loop_match++);

                    MpmEndMatch *em;
                    for (em = p->em; em; em = em->next) {
                        SCLogDebug("em %p pid %" PRIu32 ", sid "
                                   "%"PRIu32"", em, em->id, em->sig_id);
                        if (MpmMatchAppend(mpm_thread_ctx, pmq,
                                           em,
                                           &mpm_thread_ctx->match[em->id],
                                           i, p->len))
                            matches++;
                    }
                } else {
                    COUNT(tctx->scan_stat_loop_no_match++);
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

uint32_t B2gCudaScan(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                     PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen)
{
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx->ctx;
#ifdef B2G_CUDA_COUNTERS
    B2gCudaThreadCtx *tctx = (B2gCudaThreadCtx *)mpm_thread_ctx->ctx;
#endif
    uint32_t pos = 0, matches = 0;
    B2G_CUDA_TYPE d;
    uint32_t j;

    COUNT(tctx->scan_stat_calls++);
    COUNT(tctx->scan_stat_m_total+=ctx->scan_m);

    if (buflen < ctx->scan_m)
        return 0;

    while (pos <= (buflen - ctx->scan_m)) {
        j = ctx->scan_m - 1;
        d = ~0;

        do {
            uint16_t h = B2G_CUDA_HASH16(u8_tolower(buf[pos + j - 1]),
                                         u8_tolower(buf[pos + j]));
            d = ((d << 1) & ctx->scan_B2G[h]);
            j = j - 1;
        } while (d != 0 && j != 0);

        /* (partial) match, move on to verification */
        if (d != 0) {
            COUNT(tctx->scan_stat_d0++);

            /* get our patterns from the hash */
            uint16_t h = B2G_CUDA_HASH16(u8_tolower(buf[pos + ctx->scan_m - 2]),
                                         u8_tolower(buf[pos + ctx->scan_m - 1]));

            if (ctx->scan_bloom[h] != NULL) {
                COUNT(tctx->scan_stat_pminlen_calls++);
                COUNT(tctx->scan_stat_pminlen_total+=ctx->scan_pminlen[h]);

                if ((buflen - pos) < ctx->scan_pminlen[h]) {
                    goto skip_loop;
                } else {
                    COUNT(tctx->scan_stat_bloom_calls++);

                    if (BloomFilterTest(ctx->scan_bloom[h], buf+pos,
                                        ctx->scan_pminlen[h]) == 0) {
                        COUNT(tctx->scan_stat_bloom_hits++);

                        goto skip_loop;
                    }
                }
            }

            B2gCudaHashItem *hi = ctx->scan_hash[h], *thi;
            for (thi = hi; thi != NULL; thi = thi->nxt) {
                COUNT(tctx->scan_stat_d0_hashloop++);
                B2gCudaPattern *p = ctx->parray[thi->idx];

                if (p->flags & B2G_CUDA_NOCASE) {
                    if (buflen - pos < p->len)
                        continue;

                    if (memcmp_lowercase(p->ci, buf+pos, p->len) == 0) {
                        COUNT(tctx->scan_stat_loop_match++);

                        MpmEndMatch *em;
                        for (em = p->em; em; em = em->next) {
                            if (MpmMatchAppend(mpm_thread_ctx, pmq, em,
                                               &mpm_thread_ctx->match[em->id],
                                               pos, p->len))
                                matches++;
                        }
                    } else {
                        COUNT(tctx->scan_stat_loop_no_match++);
                    }
                } else {
                    if (buflen - pos < p->len)
                        continue;

                    if (memcmp(p->cs, buf+pos, p->len) == 0) {
                        COUNT(tctx->scan_stat_loop_match++);

                        MpmEndMatch *em;
                        for (em = p->em; em; em = em->next) {
                            if (MpmMatchAppend(mpm_thread_ctx, pmq, em,
                                               &mpm_thread_ctx->match[em->id],
                                               pos, p->len))
                                matches++;
                        }
                    } else {
                        COUNT(tctx->scan_stat_loop_no_match++);
                    }
                }
            }
skip_loop:
            pos = pos + 1;
        } else {
            COUNT(tctx->scan_stat_num_shift++);
            COUNT(tctx->scan_stat_total_shift += (j + 1));

            pos = pos + j + 1;
        }
    }

    return matches;
}

#ifdef B2G_CUDA_SCAN2
uint32_t B2gCudaScan2(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
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
        hi = &ctx->scan_hash1[h8];

        if (hi->flags & 0x01) {
            for (thi = hi; thi != NULL; thi = thi->nxt) {
                p = ctx->parray[thi->idx];

                if (p->flags & B2G_CUDA_NOCASE) {
                    if (h8 == p->ci[0]) {
                        for (em = p->em; em; em = em->next) {
                            if (MpmMatchAppend(mpm_thread_ctx, pmq, em,
                                               &mpm_thread_ctx->match[em->id],
                                               (buf+1 - bufmin), p->len))
                                cnt++;
                        }
                    }
                } else {
                    if (*buf == p->cs[0]) {
                        for (em = p->em; em; em = em->next) {
                            if (MpmMatchAppend(mpm_thread_ctx, pmq, em,
                                               &mpm_thread_ctx->match[em->id],
                                               (buf+1 - bufmin), p->len))
                                cnt++;
                        }
                    }
                }
            }
        }

        /* save one conversion by reusing h8 */
        uint16_t h16 = B2G_CUDA_HASH16(h8, u8_tolower(*(buf+1)));
        hi = ctx->scan_hash2[h16];

        for (thi = hi; thi != NULL; thi = thi->nxt) {
            p = ctx->parray[thi->idx];

            if (p->flags & B2G_CUDA_NOCASE) {
                if (h8 == p->ci[0] && u8_tolower(*(buf+1)) == p->ci[1]) {
                    for (em = p->em; em; em = em->next) {
                        if (MpmMatchAppend(mpm_thread_ctx, pmq, em,
                                           &mpm_thread_ctx->match[em->id],
                                           (buf+1 - bufmin), p->len))
                            cnt++;
                    }
                }
            } else {
                if (*buf == p->cs[0] && *(buf+1) == p->cs[1]) {
                    for (em = p->em; em; em = em->next) {
                        if (MpmMatchAppend(mpm_thread_ctx, pmq, em,
                                           &mpm_thread_ctx->match[em->id],
                                           (buf+1 - bufmin), p->len))
                            cnt++;
                    }
                }
            }
        }
        buf += 1;
    }

    if (ctx->scan_x_pat_cnt > 0) {
        /* Pass bufmin on because buf no longer points to the
         * start of the buffer. */
        cnt += ctx->MBScan(mpm_ctx, mpm_thread_ctx, pmq, bufmin, buflen);
    }

    return cnt;
}
#endif

uint32_t B2gCudaScan1(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                  PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen)
{
    SCEnter();

    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx->ctx;
    uint8_t *bufmin = buf;
    uint8_t *bufend = buf + buflen - 1;
    uint32_t cnt = 0;
    B2gCudaPattern *p;
    MpmEndMatch *em;
    B2gCudaHashItem *thi, *hi;

    if (buflen == 0)
        SCReturnUInt(0);

    while (buf <= bufend) {
        uint8_t h = u8_tolower(*buf);
        hi = &ctx->scan_hash1[h];

        if (hi->flags & 0x01) {
            for (thi = hi; thi != NULL; thi = thi->nxt) {
                p = ctx->parray[thi->idx];

                if (p->len != 1)
                    continue;

                if (p->flags & B2G_CUDA_NOCASE) {
                    if (u8_tolower(*buf) == p->ci[0]) {
                        for (em = p->em; em; em = em->next) {
                            if (MpmMatchAppend(mpm_thread_ctx, pmq, em,
                                               &mpm_thread_ctx->match[em->id],
                                               (buf+1 - bufmin), p->len))
                                cnt++;
                        }
                    }
                } else {
                    if (*buf == p->cs[0]) {
                        for (em = p->em; em; em = em->next) {
                            if (MpmMatchAppend(mpm_thread_ctx, pmq, em,
                                               &mpm_thread_ctx->match[em->id],
                                               (buf+1 - bufmin), p->len))
                                cnt++;
                        }
                    }
                }
            }
        }
        buf += 1;
    }

#ifdef B2G_CUDA_SCAN2
    if (ctx->scan_2_pat_cnt) {
        /* Pass bufmin on because buf no longer points to the
         * start of the buffer. */
        cnt += ctx->MBScan2(mpm_ctx, mpm_thread_ctx, pmq, bufmin, buflen);
    } else
#endif
    if (ctx->scan_x_pat_cnt) {
        cnt += ctx->MBScan(mpm_ctx, mpm_thread_ctx, pmq, bufmin, buflen);
    }

    SCReturnUInt(cnt);
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

    if (buflen < ctx->search_m)
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

    if (SCCudaParamSetv(ctx->cuda_search_kernel, B2G_CUDA_KERNEL_ARG0_OFFSET,
                        (void *)&cuda_offsets, sizeof(void *)) == -1) {
        goto error;
    }

    if (SCCudaParamSetv(ctx->cuda_search_kernel, B2G_CUDA_KERNEL_ARG1_OFFSET,
                        (void *)&ctx->cuda_search_B2G, sizeof(void *)) == -1) {
        goto error;
    }

    if (SCCudaParamSetv(ctx->cuda_search_kernel, B2G_CUDA_KERNEL_ARG3_OFFSET,
                        (void *)&cuda_buf, sizeof(void *)) == -1) {
        goto error;
    }

    if (SCCudaParamSeti(ctx->cuda_search_kernel, B2G_CUDA_KERNEL_ARG4_OFFSET,
                        buflen) == -1) {
        goto error;
    }

    if (SCCudaParamSeti(ctx->cuda_search_kernel, B2G_CUDA_KERNEL_ARG5_OFFSET,
                        ctx->search_m) == -1) {
        goto error;
    }

    if (SCCudaParamSetSize(ctx->cuda_search_kernel, B2G_CUDA_KERNEL_TOTAL_ARG_SIZE) == -1)
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
        //printf("%d ", i);
        /* get our patterns from the hash */
        h = B2G_CUDA_HASH16(u8_tolower(buf[i + ctx->search_m - 2]),
                            u8_tolower(buf[i + ctx->search_m - 1]));

        if (ctx->search_bloom[h] != NULL) {
            COUNT(tctx->search_stat_pminlen_calls++);
            COUNT(tctx->search_stat_pminlen_total += ctx->search_pminlen[h]);

            if ((buflen - i) < ctx->search_pminlen[h]) {
                continue;
            } else {
                COUNT(tctx->search_stat_bloom_calls++);

                if (BloomFilterTest(ctx->search_bloom[h], buf + i,
                                    ctx->search_pminlen[h]) == 0) {
                    COUNT(tctx->search_stat_bloom_hits++);
                    continue;
                }
            }
        }

        B2gCudaHashItem *hi = ctx->search_hash[h], *thi;
        for (thi = hi; thi != NULL; thi = thi->nxt) {
            COUNT(tctx->search_stat_d0_hashloop++);
            B2gCudaPattern *p = ctx->parray[thi->idx];

            if (p->flags & B2G_CUDA_NOCASE) {
                if (buflen - i < p->len)
                    continue;

                if (memcmp_lowercase(p->ci, buf + i, p->len) == 0) {
                    COUNT(tctx->search_stat_loop_match++);

                    MpmEndMatch *em;
                    for (em = p->em; em; em = em->next) {
                        if (MpmMatchAppend(mpm_thread_ctx, pmq, em,
                                           &mpm_thread_ctx->match[em->id], i, p->len))
                            matches++;
                    }
                } else {
                    COUNT(tctx->search_stat_loop_no_match++);
                }
            } else {
                if (buflen - i < p->len)
                    continue;

                if (memcmp(p->cs, buf + i, p->len) == 0) {
                    COUNT(tctx->search_stat_loop_match++);

                    MpmEndMatch *em;
                    for (em = p->em; em; em = em->next) {
                        if (MpmMatchAppend(mpm_thread_ctx, pmq, em,
                                           &mpm_thread_ctx->match[em->id], i, p->len))
                            matches++;
                    }
                } else {
                    COUNT(tctx->search_stat_loop_no_match++);
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
    uint32_t j;

    if (buflen < ctx->search_m)
        return 0;

    while (pos <= (buflen - ctx->search_m)) {
        j = ctx->search_m - 1;
        d = ~0;

        do {
            uint16_t h = B2G_CUDA_HASH16(u8_tolower(buf[pos + j - 1]),
                                         u8_tolower(buf[pos + j]));
            d &= ctx->search_B2G[h];
            d <<= 1;
            j = j - 1;
        } while (d != 0 && j != 0);

        /* (partial) match, move on to verification */
        if (d != 0) {
            COUNT(tctx->search_stat_d0++);

            /* get our patterns from the hash */
            uint16_t h = B2G_CUDA_HASH16(u8_tolower(buf[pos + ctx->search_m - 2]),
                                         u8_tolower(buf[pos + ctx->search_m - 1]));

            if (ctx->scan_bloom[h] != NULL) {
                COUNT(tctx->scan_stat_pminlen_calls++);
                COUNT(tctx->scan_stat_pminlen_total+=ctx->scan_pminlen[h]);

                if ((buflen - pos) < ctx->scan_pminlen[h]) {
                    goto skip_loop;
                } else {
                    COUNT(tctx->scan_stat_bloom_calls++);

                    if (BloomFilterTest(ctx->scan_bloom[h], buf+pos,
                                        ctx->scan_pminlen[h]) == 0) {
                        COUNT(tctx->scan_stat_bloom_hits++);

                        goto skip_loop;
                    }
                }
            }

            B2gCudaHashItem *hi = ctx->search_hash[h], *thi;
            for (thi = hi; thi != NULL; thi = thi->nxt) {
                B2gCudaPattern *p = ctx->parray[thi->idx];
                if (p->flags & B2G_CUDA_NOCASE) {
                    if (buflen - pos < p->len)
                        continue;

                    if (memcmp_lowercase(p->ci, buf+pos, p->len) == 0) {
                        COUNT(tctx->search_stat_loop_match++);

                        MpmEndMatch *em;
                        for (em = p->em; em; em = em->next) {
                            if (MpmMatchAppend(mpm_thread_ctx, pmq, em,
                                               &mpm_thread_ctx->match[em->id],
                                               pos, p->len))
                                matches++;
                        }

                    } else {
                        COUNT(tctx->search_stat_loop_no_match++);
                    }
                } else {
                    if (buflen - pos < p->len)
                        continue;

                    if (memcmp(p->cs, buf+pos, p->len) == 0) {
                        COUNT(tctx->search_stat_loop_match++);

                        MpmEndMatch *em;
                        for (em = p->em; em; em = em->next) {
                            if (MpmMatchAppend(mpm_thread_ctx, pmq, em,
                                               &mpm_thread_ctx->match[em->id],
                                               pos, p->len))
                                matches++;
                        }

                    } else {
                        COUNT(tctx->search_stat_loop_no_match++);
                    }
                }
            }

skip_loop:
            pos = pos + 1;
        } else {
            COUNT(tctx->search_stat_num_shift++);
            COUNT(tctx->search_stat_total_shift += (j + 1));
            pos = pos + j + 1;
        }
    }

    return matches;
}

uint32_t B2gCudaSearch1(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
                        PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen)
{
    SCEnter();

    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx->ctx;
    uint8_t *bufmin = buf;
    uint8_t *bufend = buf + buflen - 1;
    uint32_t cnt = 0;
    B2gCudaPattern *p;
    MpmEndMatch *em;
    B2gCudaHashItem *thi, *hi;

    if (buflen == 0)
        SCReturnUInt(0);

    while (buf <= bufend) {
        uint8_t h = u8_tolower(*buf);
        hi = &ctx->search_hash1[h];

        if (hi->flags & 0x01) {
            for (thi = hi; thi != NULL; thi = thi->nxt) {
                p = ctx->parray[thi->idx];

                if (p->len != 1)
                    continue;

                if (p->flags & B2G_CUDA_NOCASE) {
                    if (u8_tolower(*buf) == p->ci[0]) {
                        for (em = p->em; em; em = em->next) {
                            if (MpmMatchAppend(mpm_thread_ctx, pmq, em,
                                               &mpm_thread_ctx->match[em->id],
                                               (buf+1 - bufmin), p->len))
                                cnt++;
                        }
                    }
                } else {
                    if (*buf == p->cs[0]) {
                        for (em = p->em; em; em = em->next) {
                            if (MpmMatchAppend(mpm_thread_ctx, pmq, em,
                                               &mpm_thread_ctx->match[em->id],
                                               (buf+1 - bufmin), p->len))
                                cnt++;
                        }
                    }
                }
            }
        }
        buf += 1;
    }

    if (mpm_ctx->search_maxlen > 1) {
        /* Pass bufmin on because buf no longer points to the
         * start of the buffer. */
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

    if (p->cuda_search) {
        p->cuda_matches = mpm_table[p->cuda_mpm_ctx->mpm_type].Search(p->cuda_mpm_ctx,
                                                              p->cuda_mtc,
                                                              p->cuda_pmq,
                                                              p->payload,
                                                              p->payload_len);
    } else {
        p->cuda_matches = mpm_table[p->cuda_mpm_ctx->mpm_type].Scan(p->cuda_mpm_ctx,
                                                            p->cuda_mtc,
                                                            p->cuda_pmq,
                                                            p->payload,
                                                            p->payload_len);
    }

    /* signal the client that the result is ready */
    SCCondSignal(&p->cuda_cond_q);
    /* wait for the client indication that it has read the results.  If the
     * client still hasn't sent the indication, signal it again and do so
     * every 50 microseconds */
    while (p->cuda_done == 0) {
        SCCondSignal(&p->cuda_cond_q);
        usleep(50);
    }

    if (p->cuda_free_packet == 1) {
        free(p);
    }

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

#ifdef UNITTESTS

int B2gCudaStartDispatcherThreadRC(const char *name)
{
    SCCudaHlModuleData *data = NULL;
    TmModule *tm_module = NULL;

    if (name == NULL) {
        SCLogError(SC_INVALID_ARGUMENTS, "Error invalid arguments.  "
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
    free(tv_CMB2_RC);
    tv_CMB2_RC = NULL;

    return;
}

/**
 * \brief Hacks for the tests.  While running the tests, we sometimes need to
 *        kill the threads to make them pop the cuda contexts.  We don't need
 *        these under normal running.
 */
void B2gCudaKillDispatcherThreadAPC(void)
{
    if (tv_CMB2_APC == NULL)
        return;

    TmThreadKillThread(tv_CMB2_APC);
    TmThreadRemove(tv_CMB2_APC, tv_CMB2_APC->type);
    free(tv_CMB2_APC);
    tv_CMB2_APC = NULL;

    return;
}

int B2gCudaStartDispatcherThreadAPC(const char *name)
{
    SCCudaHlModuleData *data = NULL;
    TmModule *tm_module = NULL;

    if (name == NULL) {
        SCLogError(SC_INVALID_ARGUMENTS, "Error invalid arguments.  "
                   "name NULL");
        return -1;
    }

    if (tv_CMB2_APC != NULL) {
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
    tv_CMB2_APC = TmThreadCreatePacketHandler("Cuda_Mpm_B2g_APC",
                                              "app_proto_content_mpm_inqueue", "simple",
                                              NULL, NULL,
                                              "1slot_noout");
    if (tv_CMB2_APC == NULL) {
        SCLogError(SC_ERR_TM_THREADS_ERROR, "ERROR: TmThreadsCreate failed");
        exit(EXIT_FAILURE);
    }
    tv_CMB2_APC->inq->writer_cnt++;

    tm_module = TmModuleGetByName("Cuda_Mpm_B2g");
    if (tm_module == NULL) {
        SCLogError(SC_ERR_TM_MODULES_ERROR,
                   "ERROR: TmModuleGetByName failed for Cuda_Mpm_B2g_APC");
        exit(EXIT_FAILURE);
    }
    Tm1SlotSetFunc(tv_CMB2_APC, tm_module, data);

    if (TmThreadSpawn(tv_CMB2_APC) != TM_ECODE_OK) {
        SCLogError(SC_ERR_TM_THREADS_ERROR, "ERROR: TmThreadSpawn failed");
        exit(EXIT_FAILURE);
    }

    TmThreadContinue(tv_CMB2_APC);

    return 0;
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

void B2gCudaPushPacketTo_tv_CMB2_APC(Packet *p)
{
    PacketQueue *q = &trans_q[tv_CMB2_APC->inq->id];

    SCMutexLock(&q->mutex_q);
    PacketEnqueue(q, p);
    SCCondSignal(&q->cond_q);
    SCMutexUnlock(&q->mutex_q);

    return;
}

/*********************************Unittests************************************/

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

    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"one", 3, 0, 0, 1, 1) == -1)
        goto end;
    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"two", 3, 0, 0, 2, 1) == -1)
        goto end;
    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"three", 5, 0, 0, 3, 1) == -1)
        goto end;
    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"four", 4, 0, 0, 4, 1) == -1)
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

    if (B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"one", 3, 0, 0, 1, 1, 0) == -1)
        goto end;
    if (B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"two", 3, 0, 0, 2, 1, 0) == -1)
        goto end;
    if (B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"three", 5, 0, 0, 3, 1, 0) == -1)
        goto end;
    if (B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"four", 4, 0, 0, 4, 1, 0) == -1)
        goto end;

    if (B2gCudaPreparePatterns(&mpm_ctx) == -1)
        goto end;
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 4 /* 4 patterns */);

    char *string = "onetwothreeaaaaoneaatwobbbthrbsonwehowvonwoonsldffoursadnothreewtowoneowtwo";
    result = (B2gCudaScanBNDMq(&mpm_ctx, &mpm_thread_ctx, NULL,
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

    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"onee", 4, 0, 0, 1, 1) == -1)
        goto end;
    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"twoo", 4, 0, 0, 2, 1) == -1)
        goto end;
    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"three", 5, 0, 0, 3, 1) == -1)
        goto end;
    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"four", 4, 0, 0, 4, 1) == -1)
        goto end;
    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"onee", 4, 0, 0, 1, 2) == -1)
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

    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"one", 3, 0, 0, 1, 1) == -1)
        goto end;
    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"two", 3, 0, 0, 2, 1) == -1)
        goto end;
    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"three", 5, 0, 0, 3, 1) == -1)
        goto end;
    if (B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"four", 4, 0, 0, 4, 1) == -1)
        goto end;

    if (B2gCudaPreparePatterns(&mpm_ctx) == -1)
        goto end;
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 4 /* 4 patterns */);

    char *string = "onetwothreeaaaaoneaatwobbbthrbsonwehowvonwfouoonsldffoursadnothreewtowoneowtwo";
    result = (B2gCudaSearchBNDMq(&mpm_ctx, &mpm_thread_ctx,
                                 NULL, (uint8_t *)string, strlen(string)) == 9);

    result = 1;

 end:
    MpmMatchCleanup(&mpm_thread_ctx);
    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestScan01(void)
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
    B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)buf, strlen(buf));

    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 1)
        result = 1;

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);

    return result;
}

static int B2gCudaTestScan02(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;
    char *buf = "abcdefghjiklmnopqrstuvwxyz";

    B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"abce", 4, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)buf, strlen(buf));

    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 0)
        result = 1;

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);

    return result;
}

static int B2gCudaTestScan03(void)
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
    B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"bcde", 4, 0, 0, 1, 0, 0);
    B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"fghj", 4, 0, 0, 2, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 3 /* 3 patterns */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)buf, strlen(buf));

    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 3)
        result = 1;

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);

    return result;
}

/**
 * \test Test patterns longer than 'm'. M is 4 here.
 */
static int B2gCudaTestScan04(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;
    char *buf = "abcdefghjiklmnopqrstuvwxyz";

    B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"bcdegh", 6, 0, 0, 1, 0, 0);
    B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"fghjxyz", 7, 0, 0, 2, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 3 /* 3 patterns */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)buf, strlen(buf));

    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 1)
        result = 1;

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

/**
 * \test Case insensitive test patterns longer than 'm'. M is 4 here.
 */
static int B2gCudaTestScan05(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;
    char *buf = "abcdefghjiklmnopqrstuvwxyz";

    B2gCudaAddScanPatternCI(&mpm_ctx, (uint8_t *)"ABCD", 4, 0, 0, 0, 0, 0);
    B2gCudaAddScanPatternCI(&mpm_ctx, (uint8_t *)"bCdEfG", 6, 0, 0, 1, 0, 0);
    B2gCudaAddScanPatternCI(&mpm_ctx, (uint8_t *)"fghJikl", 7, 0, 0, 2, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 3 /* 3 patterns */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)buf, strlen(buf));

    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 3)
        result = 1;

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);

    return result;
}

static int B2gCudaTestScan06(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;
    char *buf = "abcd";

    B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)buf, strlen(buf));

    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 1)
        result = 1;

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);

    return result;
}

static int B2gCudaTestScan07(void)
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
    B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"A", 1, 0, 0, 0, 0, 0);
    /* should match 29 times */
    B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 1, 0, 0);
    /* should match 28 times */
    B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"AAA", 3, 0, 0, 2, 0, 0);
    /* should match 26 times */
    B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"AAAAA", 5, 0, 0, 3, 0, 0);
    /* should match 21 times */
    B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"AAAAAAAAAA", 10, 0, 0, 4, 0, 0);
    /* should match 1 time */
    B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 30, 0, 0, 5, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 6 /* 6 patterns */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)buf, strlen(buf));

    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 135)
        result = 1;

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);

    return result;
}

static int B2gCudaTestScan08(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0); /* 1 match */

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"a", 1);

    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

/* we segfault with this test */
static int B2gCudaTestScan09(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 match */
    B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"ab", 2, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"ab", 2);

    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestScan10(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"abcdefgh", 8, 0, 0, 0, 0, 0); /* 1 match */

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    char *buf = "01234567890123456789012345678901234567890123456789"
                "01234567890123456789012345678901234567890123456789"
                "abcdefgh"
                "01234567890123456789012345678901234567890123456789"
                "01234567890123456789012345678901234567890123456789";
    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)buf, strlen(buf));

    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestScan11(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 match */
    B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"abcde", 5, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 2 /* 2 patterns */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL,
                             (uint8_t *)"abcdefghijklmnopqrstuvwxyz", 26);

    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestScan12(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"wxyz", 4, 0, 0, 0, 0, 0); /* 1 match */
    B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"vwxyz", 5, 0, 0, 0, 0, 0); /* 1 match */

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 2 /* 2 patterns */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL,
                             (uint8_t *)"abcdefghijklmnopqrstuvwxyz", 26);

    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestScan13(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 match */
    B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"abcdefghijklmnopqrstuvwxyzABCD",
                            30, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL,
                             (uint8_t *)"abcdefghijklmnopqrstuvwxyzABCD", 30);

    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestScan14(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 match */
    B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"abcdefghijklmnopqrstuvwxyzABCDE",
                            31, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL,
                             (uint8_t *)"abcdefghijklmnopqrstuvwxyzABCDE", 31);

    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestScan15(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 match */
    B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"abcdefghijklmnopqrstuvwxyzABCDEF",
                            32, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL,
                             (uint8_t *)"abcdefghijklmnopqrstuvwxyzABCDEF", 32);

    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestScan16(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 match */
    B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"abcdefghijklmnopqrstuvwxyzABC",
                            29, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL,
                             (uint8_t *)"abcdefghijklmnopqrstuvwxyzABC", 29);

    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestScan17(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"abcdefghijklmnopqrstuvwxyzAB",
                            28, 0, 0, 0, 0, 0); /* 1 match */

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL,
                             (uint8_t *)"abcdefghijklmnopqrstuvwxyzAB", 28);

    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestScan18(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 match */
    B2gCudaAddScanPatternCS(&mpm_ctx,
                            (uint8_t *)"abcde""fghij""klmno""pqrst""uvwxy""z",
                            26, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL,
                             (uint8_t *)"abcde""fghij""klmno""pqrst""uvwxy""z",
                             26);

    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestScan19(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 */
    B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                            30, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 patterns */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL,
                             (uint8_t *)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 30);

    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestScan20(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 */
    B2gCudaAddScanPatternCS(&mpm_ctx,
                            (uint8_t *)"AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AA",
                            32, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 patterns */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL,
                             (uint8_t *)"AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AA",
                             32);

    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gCudaTestScan21(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 */
    B2gCudaAddScanPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 patterns */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"AA", 2);

    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

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

    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL,
                               (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

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

    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abce", 4, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL,
                               (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

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

    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0);
    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"bcde", 4, 0, 0, 1, 0);
    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"fghj", 4, 0, 0, 2, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 3 /* 3 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL,
                               (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    MpmMatchCleanup(&mpm_thread_ctx);

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
static int B2gCudaTestSearch04(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0);
    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"bcdegh", 6, 0, 0, 1, 0);
    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"fghjxyz", 7, 0, 0, 2, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 3 /* 3 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL,
                               (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    MpmMatchCleanup(&mpm_thread_ctx);

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
static int B2gCudaTestSearch05(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 match */
    B2gCudaAddPatternCI(&mpm_ctx, (uint8_t *)"ABCD", 4, 0, 0, 0, 0);
    /* 1 match */
    B2gCudaAddPatternCI(&mpm_ctx, (uint8_t *)"bCdEfG", 6, 0, 0, 1, 0);
    /* 1 match */
    B2gCudaAddPatternCI(&mpm_ctx, (uint8_t *)"fghJikl", 7, 0, 0, 2, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 3 /* 3 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL,
                               (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

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

    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcd", 4);

    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

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

    /* should match 30 times */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"A", 1, 0, 0, 0, 0);
    /* should match 29 times */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 1, 0);
    /* should match 28 times */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"AAA", 3, 0, 0, 2, 0);
    /* 26 */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAA", 5, 0, 0, 3, 0);
    /* 21 */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAAAAAAA", 10, 0, 0, 4, 0);
    /* 1 */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        30, 0, 0, 5, 0);
    /* total matches: 135 */

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 6 /* 6 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL,
                               (uint8_t *)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 30);

    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 135)
        result = 1;
    else
        printf("135 != %" PRIu32 " ",cnt);

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

    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"a", 1);

    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

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
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"ab", 2, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"ab", 2);

    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gCudaThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gCudaDestroyCtx(&mpm_ctx);
    return result;
}

/* 1 match */
static int B2gCudaTestSearch10(void)
{
    int result = 0;
    int module_handle = SCCudaHlGetModuleHandle("B2G_CUDA_TEST");
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2G_CUDA, module_handle);
    B2gCudaCtx *ctx = (B2gCudaCtx *)mpm_ctx.ctx;

    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abcdefgh", 8, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    char *buf = "01234567890123456789012345678901234567890123456789"
                "01234567890123456789012345678901234567890123456789"
                "abcdefgh"
                "01234567890123456789012345678901234567890123456789"
                "01234567890123456789012345678901234567890123456789";
    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)buf,
                               strlen(buf));

    MpmMatchCleanup(&mpm_thread_ctx);

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
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0);
    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"abcde", 5, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 2 /* 2 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL,
                               (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    MpmMatchCleanup(&mpm_thread_ctx);

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

    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"wxyz", 4, 0, 0, 0, 0);
    /* 1 match */
    B2gCudaAddPatternCS(&mpm_ctx, (uint8_t *)"vwxyz", 5, 0, 0, 0, 0);

    B2gCudaPreparePatterns(&mpm_ctx);
    B2gCudaThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 2 /* 2 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL,
                               (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    MpmMatchCleanup(&mpm_thread_ctx);

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
    UtRegisterTest("B2gCudaTestScan01", B2gCudaTestScan01, 1);
    UtRegisterTest("B2gCudaTestScan02", B2gCudaTestScan02, 1);
    UtRegisterTest("B2gCudaTestScan03", B2gCudaTestScan03, 1);
    UtRegisterTest("B2gCudaTestScan04", B2gCudaTestScan04, 1);
    UtRegisterTest("B2gCudaTestScan05", B2gCudaTestScan05, 1);
    UtRegisterTest("B2gCudaTestScan06", B2gCudaTestScan06, 1);
    UtRegisterTest("B2gCudaTestScan07", B2gCudaTestScan07, 1);
    UtRegisterTest("B2gCudaTestScan08", B2gCudaTestScan08, 1);
    UtRegisterTest("B2gCudaTestScan09", B2gCudaTestScan09, 1);
    UtRegisterTest("B2gCudaTestScan10", B2gCudaTestScan10, 1);
    UtRegisterTest("B2gCudaTestScan11", B2gCudaTestScan11, 1);
    UtRegisterTest("B2gCudaTestScan12", B2gCudaTestScan12, 1);
    UtRegisterTest("B2gCudaTestScan13", B2gCudaTestScan13, 1);

    UtRegisterTest("B2gCudaTestScan14", B2gCudaTestScan14, 1);
    UtRegisterTest("B2gCudaTestScan15", B2gCudaTestScan15, 1);
    UtRegisterTest("B2gCudaTestScan16", B2gCudaTestScan16, 1);
    UtRegisterTest("B2gCudaTestScan17", B2gCudaTestScan17, 1);
    UtRegisterTest("B2gCudaTestScan18", B2gCudaTestScan18, 1);
    UtRegisterTest("B2gCudaTestScan19", B2gCudaTestScan19, 1);
    UtRegisterTest("B2gCudaTestScan20", B2gCudaTestScan20, 1);
    UtRegisterTest("B2gCudaTestScan21", B2gCudaTestScan21, 1);

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
    UtRegisterTest("B2gCudaTestDeInitTestEnv", B2gCudaTestDeInitTestEnv, 1);
#endif /* UNITTESTS */
}

#endif /* __SC_CUDA_SUPPORT */
