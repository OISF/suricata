/**
 * Copyright (c) 2010 Open Information Security Foundation.
 *
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * \todo
 *       1 Implement a gpu version of aho-corasick.  That should get rid of a
 *         lot of post processing and pattern_chopping, and we don't have to
 *         deal with one or two byte patterns. (currently in process)
 *       2 Use texture/shared memory.  This should be handled along with 1 and 6.
 *       3 Currently a lot of packets(~17k) are getting stuck on the detection
 *         thread, which is a major bottleneck.  Introduce bypass detection
 *         threads for these 15k non buffered packets and check how the alerts
 *         are affected by this(out of sequence handling by detection threads).
 *       4 Test the use of mapped memory(if possible anywhere).
 *       5 Check parallelising memcopies with kernel execution.
 *       6 Test this feature - Rearrange the packet stream(either on cpu or gpu),
 *         where each block in the gpu can access the packet with non-coalesced
 *         reads.
 *         2 packets p1 -> aabb ccdd
 *                   p2 -> eeff gghh
 *
 *         stream -> aabbeeffccddgghh.
 *
 *         Modify the block size to 16 threads for CC < 2.0 devices and 32 for
 *         for >= 2.0.
 *
 *         The rearrangement of packet stream can be done on the gpu, with no
 *         perf degradation, using coalesced reads.  Padding packets need to
 *         be addressed though.
 *         (Need to give more thought to this task).
 *
 *         -- Feel free to pick any task from the agenda, but please
 *         drop a mail to dev mailing list(or directly to the dev team).  Better
 *         yet, open a feature request on our bug/feature tracker
 *         (https://redmine.openinfosecfoundation.org/issues).  Will be a mess if
 *         2 or more devs end up working on the same task or related tasks.
 */

/* compile in, only if we have a CUDA enabled on this machine */
#ifdef __SC_CUDA_SUPPORT__

#include "suricata-common.h"
#include "suricata.h"

#include "detect.h"
#include "decode.h"
#include "flow.h"
#include "data-queue.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-queuehandlers.h"
#include "tm-threads.h"

#include "cuda-packet-batcher.h"
#include "conf.h"

#include "util-error.h"
#include "util-debug.h"
#include "util-unittest.h"

#include "util-mpm-b2g-cuda.h"
#include "util-cuda-handlers.h"
#include "detect-engine-address.h"
#include "detect-engine-port.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "tm-threads.h"
#include "tmqh-packetpool.h"
#include "util-mpm.h"

/* \todo Make this user configurable through our yaml file.  Also provide options
 * where this can be dynamically updated based on the traffic */
#define SC_CUDA_PB_BATCHER_ALARM_TIME 1

/* holds the inq and outq between the cuda-packet-batcher TM and the cuda b2g mpm
 * dispatcher thread */
static Tmq *tmq_inq = NULL;
static Tmq *tmq_outq = NULL;

/* holds the packet inq between the batcher TM and, the TM feeding it packets
 * in the runmode sequence.  We will need this to implement the alarm.  We will
 * have a SIG_ALRM delivered every SC_CUDA_PB_BATCHER_ALARM_TIME seconds, after
 * which we willf set a flag informing the batcher TM to queue the buffer to the
 * GPU and wake the batcher thread, in case it is waiting on a conditional for a
 * packet from the previous TM in the runmode */
static Tmq *tmq_batcher_inq = NULL;

/* used to indicate if we want to stop buffering the packets anymore.  We
 * we will need this while we want to shut the engine down
 * \todo give a better description */
static int run_batcher = 1;

/* indicates the maximum no of packets we are ready to buffer.  Theoretically the
 * maximum value held by this var can't exceed the value held by
 * "max_pending_packets".  Either ways we should make this user configurable like
 * SC_CUDA_PB_BATCHER_ALARM_TIME.  Also allow dynamic updates to this value based
 * on the traffic
 * \todo make this user configurable, as well allow dynamic update of this
 * variable based on the traffic seen */
static uint32_t buffer_packet_threshhold = 0;

/* the profile used by the cuda batcher */
static MpmCudaConf *profile = NULL;

/* flag used by the SIG_ALRM handler to indicate that the batcher TM should queue
 * the buffer to be processed by the Cuda Mpm B2g Batcher Thread for further
 * processing on the GPU */
static int queue_buffer = 0;

/* struct to configure the SIG_ALRM frequency. */
static struct itimerval itimer = {{0, 0}, {0, 0}};

static int unittest_mode = 0;

/**
 * \internal
 * \brief The SIG_ALRM handler.  We will set the "queue_buffer" flag thus
 *        informing the batcher TM that it needs to queue the buffer.  We
 *        also signal the cond var for the batcher TM inq(the one it
 *        receives packets from), incase it is waiting on the conditional
 *        for a new packet from the previous TM in the runmodes list.
 *
 * \param signum The signal number that this function just woke up to.  In
 *               our case it is SIG_ALRM.
 */
static void SCCudaPBSetQueueBufferFlag(int signum)
{
    SCLogDebug("Cuda Packet Batche alarm generated after %f seconds.  Set the"
               "queue_buffer flag and signal the cuda TM inq.",
               profile->batching_timeout);
    queue_buffer = 1;
    SCCondSignal(&((&trans_q[tmq_batcher_inq->id])->cond_q));

    return;
}

/**
 * \internal.
 * \brief Set the SIG_ALRM handler
 */
static void SCCudaPBSetBatcherAlarmTimeHandler()
{
    struct sigaction action;

    SCLogDebug("Setting the SIGALRM handler for the Cuda Batcher TM");
    action.sa_handler = SCCudaPBSetQueueBufferFlag;
    sigemptyset(&(action.sa_mask));
    sigaddset(&(action.sa_mask), SIGALRM);
    action.sa_flags = 0;
    sigaction(SIGALRM, &action, 0);

    itimer.it_value.tv_sec = profile->batching_timeout;
    itimer.it_value.tv_usec = (profile->batching_timeout
                               - (int32_t) profile->batching_timeout) * 1000000;

    return;
}

/**
 * \internal
 * \brief Reset the batcher alarm.
 */
static inline void SCCudaPBResetBatcherAlarm()
{
    queue_buffer = 0;

    /* if we are running unittests, don't set the alarm handler.  It will only
     * cause a seg fault if the tests take too long */
    if (!unittest_mode) {
        /* \todo We could update itimer dynamically based on the traffic */
        setitimer(ITIMER_REAL, &itimer, NULL);
    }
}

/**
 * \internal
 * \brief Used to retrieve the Signature Group Head for a packet.
 *
 * \param de_ctx Pointer the detection engine context to search for the
 *               sgh for an incoming packet.
 * \param p      Pointer to the incoming packet for which we will have to
 *               search for a sgh.
 *
 * \retval sgh Pointer to the relevant matching sgh for the Packet.
 */
static SigGroupHead *SCCudaPBGetSgh(DetectEngineCtx *de_ctx, Packet *p)
{
    int f;
    SigGroupHead *sgh = NULL;

    /* select the flow_gh */
    if (p->flowflags & FLOW_PKT_TOCLIENT)
        f = 0;
    else
        f = 1;

    /* find the right mpm instance */
    DetectAddress *ag = DetectAddressLookupInHead(de_ctx->flow_gh[f].src_gh[p->proto], &p->src);
    if (ag != NULL) {
        /* source group found, lets try a dst group */
        ag = DetectAddressLookupInHead(ag->dst_gh,&p->dst);
        if (ag != NULL) {
            if (ag->port == NULL) {
                SCLogDebug("we don't have ports");
                sgh = ag->sh;
            } else {
                SCLogDebug("we have ports");

                DetectPort *sport = DetectPortLookupGroup(ag->port,p->sp);
                if (sport != NULL) {
                    DetectPort *dport = DetectPortLookupGroup(sport->dst_ph, p->dp);
                    if (dport != NULL) {
                        sgh = dport->sh;
                    } else {
                        SCLogDebug("no dst port group found for the packet with dp %"PRIu16, p->dp);
                    }
                } else {
                    SCLogDebug("no src port group found for the packet with sp %"PRIu16, p->sp);
                }
            }
        } else {
            SCLogDebug("no dst address group found for the packet");
        }
    } else {
        SCLogDebug("no src address group found for the packet");
    }

    return sgh;
}

/**
 * \internal
 * \brief Handles the queuing of the buffer from this batcher TM to the cuda
 *        mpm b2g dispatcher TM.
 *
 * \tctx The batcher thread context that holds the current operational buffer
 *       which has to be buffered by this function.
 */
static void SCCudaPBQueueBuffer(SCCudaPBThreadCtx *tctx)
{
    SCCudaPBPacketsBuffer *pb = (SCCudaPBPacketsBuffer *)tctx->curr_pb;
    uint32_t nop_in_buffer = pb->nop_in_buffer;
    uint32_t *packets_offset_buffer = pb->packets_offset_buffer;
    uint32_t offset = *(packets_offset_buffer + nop_in_buffer - 1);
    SCCudaPBPacketDataForGPU *last_packet = (SCCudaPBPacketDataForGPU *)(pb->packets_buffer +
                                                                         offset);

    /* if we have no packets buffered in so far, get out */
    if (pb->nop_in_buffer == 0) {
        SCLogDebug("No packets buffered in so far in the cuda buffer.  Returning");
        return;
    }

    /* calculate the total length of all the packets buffered in */
    pb->packets_buffer_len = pb->packets_offset_buffer[pb->nop_in_buffer - 1] +
        sizeof(SCCudaPBPacketDataForGPUNonPayload) +
        last_packet->payload_len;

    pb->packets_total_payload_len = pb->packets_payload_offset_buffer[pb->nop_in_buffer - 1] +
        last_packet->payload_len;

    /* enqueue the buffer in the outq to be consumed by the dispatcher TM */
    SCDQDataQueue *dq_outq = &data_queues[tmq_outq->id];
    SCMutexLock(&dq_outq->mutex_q);
    SCDQDataEnqueue(dq_outq, (SCDQGenericQData *)tctx->curr_pb);
    SCCondSignal(&dq_outq->cond_q);
    SCMutexUnlock(&dq_outq->mutex_q);

    while (run_batcher) {
        /* dequeue a new buffer */
        SCDQDataQueue *dq_inq = &data_queues[tmq_inq->id];
        SCMutexLock(&dq_inq->mutex_q);
        if (dq_inq->len == 0) {
            /* if we have no data in queue, wait... */
            SCCondWait(&dq_inq->cond_q, &dq_inq->mutex_q);
        }

        if (run_batcher == 0) {
            break;
        }

        if (dq_inq->len > 0) {
            tctx->curr_pb = (SCCudaPBPacketsBuffer *)SCDQDataDequeue(dq_inq);
            tctx->curr_pb->nop_in_buffer = 0;
            tctx->curr_pb->packets_buffer_len = 0;
            tctx->curr_pb->packets_total_payload_len = 0;
            SCMutexUnlock(&dq_inq->mutex_q);
            SCLogDebug("Dequeued a new packet buffer for the cuda batcher TM");
            break;
        } else {
            /* Should only happen on signals. */
            SCMutexUnlock(&dq_inq->mutex_q);
            SCLogDebug("Unable to Relooping in the quest to dequeue new buffer");
        }
    } /* while (run_batcher) */

    return;
}

/**
 * \brief Custom slot function used by the Batcher TM.
 *
 * \param td Pointer to the ThreadVars instance.  In this case the batcher TM's
 *           ThreadVars instance.
 */
void *SCCudaPBTmThreadsSlot1(void *td)
{
    ThreadVars *tv = (ThreadVars *)td;
    TmSlot *s = (TmSlot *)tv->tm_slots;
    Packet *p = NULL;
    char run = 1;
    TmEcode r = TM_ECODE_OK;

    /* Set the thread name */
    SCSetThreadName(tv->name);

    if (tv->thread_setup_flags != 0) {
        TmThreadSetupOptions(tv);
    }

    SCLogDebug("%s starting", tv->name);

    if (s->SlotThreadInit != NULL) {
        r = s->SlotThreadInit(tv, s->slot_initdata, &s->slot_data);
        if (r != TM_ECODE_OK) {
            EngineKill();

            TmThreadsSetFlag(tv, THV_CLOSED);
            pthread_exit((void *) -1);
        }
    }
    memset(&s->slot_pre_pq, 0, sizeof(PacketQueue));
    memset(&s->slot_post_pq, 0, sizeof(PacketQueue));

    TmThreadsSetFlag(tv, THV_INIT_DONE);
    while(run) {
        TmThreadTestThreadUnPaused(tv);

        /* input a packet */
        p = tv->tmqh_in(tv);

        if (p == NULL) {
            SCLogDebug("packet is NULL for TM: %s", tv->name);
            /* the only different between the actual Slot1 function in
             * tm-threads.c and this custom Slot1 function is this call
             * here.  We need to make the call here, even if we don't
             * receive a packet from the previous stage in the runmodes.
             * This is needed in cases where the SIG_ALRM handler
             * wants us to queue the buffer to the GPU and ends up waking
             * the Batcher TM(which is waiting on a cond from the previous
             * feeder TM).  Please handle the NULL packet case in the
             * function that you now call */
            r = s->SlotFunc(tv, p, s->slot_data, NULL, NULL);
        } else {
            r = s->SlotFunc(tv, p, s->slot_data, NULL, NULL);
            /* handle error */
            if (r == TM_ECODE_FAILED) {
                TmqhOutputPacketpool(tv, p);
                TmThreadsSetFlag(tv, THV_FAILED);
                break;
            }

            /* output the packet */
            tv->tmqh_out(tv, p);
        }

        if (TmThreadsCheckFlag(tv, THV_KILL)) {
            SCPerfSyncCounters(tv, 0);
            run = 0;
        }
    }

    TmThreadWaitForFlag(tv, THV_DEINIT);

    if (s->SlotThreadExitPrintStats != NULL) {
        s->SlotThreadExitPrintStats(tv, s->slot_data);
    }

    if (s->SlotThreadDeinit != NULL) {
        r = s->SlotThreadDeinit(tv, s->slot_data);
        if (r != TM_ECODE_OK) {
            TmThreadsSetFlag(tv, THV_CLOSED);
            pthread_exit((void *) -1);
        }
    }

    SCLogDebug("%s ending", tv->name);
    TmThreadsSetFlag(tv, THV_CLOSED);
    pthread_exit((void *) 0);
}

/**
 * \brief Used to de-allocate an instance of SCCudaPBPacketsBuffer.
 *
 * \param pb Pointer to the SCCudaPacketsBuffer instance to be de-alloced.
 */
void SCCudaPBDeAllocSCCudaPBPacketsBuffer(SCCudaPBPacketsBuffer *pb)
{
    if (pb == NULL)
        return;

    if (pb->packets_buffer != NULL) {
        if (SCCudaMemFreeHost(pb->packets_buffer) == -1) {
            SCLogError(SC_ERR_CUDA_ERROR, "Error deallocating pagelocked memory: "
                       "packets_buffer");
        }
    }
    if (pb->packets_offset_buffer != NULL) {
        if (SCCudaMemFreeHost(pb->packets_offset_buffer) == -1) {
            SCLogError(SC_ERR_CUDA_ERROR, "Error deallocating pagelocked memory: "
                       "packets_offset_buffer");
        }
    }
    if (pb->packets_payload_offset_buffer != NULL) {
        if (SCCudaMemFreeHost(pb->packets_payload_offset_buffer) == -1) {
            SCLogError(SC_ERR_CUDA_ERROR, "Error deallocating pagelocked memory "
                       "packets_payload_offset_buffer");
        }
    }
    if (pb->packets_address_buffer != NULL)
        SCFree(pb->packets_address_buffer);

    SCFree(pb);

    return;
}

/**
 * \brief Allocates a new instance of SCCudaPBPacketsBuffer.
 *
 * \param pb The newly created instance of SCCudaPBPacketsBuffer.
 */
SCCudaPBPacketsBuffer *SCCudaPBAllocSCCudaPBPacketsBuffer(void)
{
    SCCudaPBPacketsBuffer *pb = SCMalloc(sizeof(SCCudaPBPacketsBuffer));
    if (pb == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    memset(pb, 0, sizeof(SCCudaPBPacketsBuffer));

    /* Register new module, needed for some unit tests */
    if (SCCudaHlGetModuleHandle("SC_CUDA_PACKET_BATCHER") == -1) {
        SCCudaHlRegisterModule("SC_CUDA_PACKET_BATCHER");
    }

    /* the buffer for the packets to be sent over to the gpu.  We allot space for
     * profile->packet_buffer_limit packets, assuming a size of
     * profile->packet_size_limit for each packet */
    SCCudaHlModuleData *data = NULL;
    data = SCCudaHlGetModuleData(SCCudaHlGetModuleHandle("SC_CUDA_PACKET_BATCHER"));
    if (data == NULL) {
        SCLogDebug("Module not registered.  To avail the benefits of this "
                   "registration facility, first register a module using "
                   "context using SCCudaHlRegisterModule(), after which you "
                   "can call this function");
        return NULL;
    }

    if (SCCudaHlGetCudaContext(&data->cuda_context, "mpm", data->handle) == -1) {
        SCLogError(SC_ERR_CUDA_HANDLER_ERROR, "Error getting cuda context");
        return NULL;
    }

    if (SCCudaCtxPushCurrent(data->cuda_context) == -1) {
        SCLogError(SC_ERR_CUDA_HANDLER_ERROR,
                   "Error pushing cuda context to allocate memory");
    }

    if (profile->page_locked) {
        if (SCCudaMemHostAlloc((void**)&pb->packets_buffer,
                               profile->packet_buffer_limit *
                               (profile->packet_size_limit +
                                sizeof(SCCudaPBPacketDataForGPUNonPayload)),
                               CU_MEMHOSTALLOC_PORTABLE |
                               CU_MEMHOSTALLOC_WRITECOMBINED) == -1) {
            SCLogError(SC_ERR_CUDA_ERROR, "Error allocating page-locked memory");
            exit(EXIT_FAILURE);
        }
    } else {
        pb->packets_buffer = SCMalloc(profile->packet_buffer_limit *
                                    (profile->packet_size_limit +
                                     sizeof(SCCudaPBPacketDataForGPUNonPayload)));
        if (pb->packets_buffer == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
    }
    memset(pb->packets_buffer, 0, profile->packet_buffer_limit *
           (profile->packet_size_limit + sizeof(SCCudaPBPacketDataForGPUNonPayload)));

    if (profile->page_locked) {
        /* used to hold the offsets of the buffered packets in the packets_buffer */
        if (SCCudaMemHostAlloc((void**)&pb->packets_offset_buffer,
                               sizeof(uint32_t) * profile->packet_buffer_limit,
                               CU_MEMHOSTALLOC_PORTABLE |
                               CU_MEMHOSTALLOC_WRITECOMBINED) == -1) {
            SCLogError(SC_ERR_CUDA_ERROR, "Error allocating page-locked memory");
            exit(EXIT_FAILURE);
        }
    } else {
        pb->packets_offset_buffer = SCMalloc(sizeof(uint32_t) *
                                           profile->packet_buffer_limit);
        if (pb->packets_offset_buffer == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
    }
    memset(pb->packets_offset_buffer, 0,
           sizeof(uint32_t) * profile->packet_buffer_limit);

    if (profile->page_locked) {
        /* used to hold the offsets of the packets payload */
        if (SCCudaMemHostAlloc((void**)&pb->packets_payload_offset_buffer,
                               sizeof(uint32_t) * profile->packet_buffer_limit,
                               CU_MEMHOSTALLOC_PORTABLE |
                               CU_MEMHOSTALLOC_WRITECOMBINED) == -1) {
            SCLogError(SC_ERR_CUDA_ERROR, "Error allocating page-locked memory");
            exit(EXIT_FAILURE);
        }
    } else {
        pb->packets_payload_offset_buffer = SCMalloc(sizeof(uint32_t) *
                                                   profile->packet_buffer_limit);
        if (pb->packets_payload_offset_buffer == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
    }
    memset(pb->packets_payload_offset_buffer, 0,
           sizeof(uint32_t) * profile->packet_buffer_limit);

    SCLogDebug("Allocated pagelocked CUDA memory");
    if (SCCudaCtxPopCurrent(NULL) == -1) {
        SCLogError(SC_ERR_CUDA_HANDLER_ERROR, "Could not pop cuda context");
    }

    /* used to hold the packet addresses for all the packets buffered inside
     * packets_buffer */
    pb->packets_address_buffer = SCMalloc(sizeof(Packet *) *
                                        profile->packet_buffer_limit);
    if (pb->packets_address_buffer == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    memset(pb->packets_address_buffer, 0, sizeof(Packet *) *
           profile->packet_buffer_limit);

    return pb;
}

/**
 * \brief Registration function for the Cuda Packet Batcher TM.
 */
void TmModuleCudaPacketBatcherRegister(void)
{
    tmm_modules[TMM_CUDA_PACKET_BATCHER].name = "CudaPacketBatcher";
    tmm_modules[TMM_CUDA_PACKET_BATCHER].ThreadInit = SCCudaPBThreadInit;
    tmm_modules[TMM_CUDA_PACKET_BATCHER].Func = SCCudaPBBatchPackets;
    tmm_modules[TMM_CUDA_PACKET_BATCHER].ThreadExitPrintStats = SCCudaPBThreadExitStats;
    tmm_modules[TMM_CUDA_PACKET_BATCHER].ThreadDeinit = SCCudaPBThreadDeInit;
    tmm_modules[TMM_CUDA_PACKET_BATCHER].RegisterTests = SCCudaPBRegisterTests;

    return;
}

/**
 * \brief The cuda batcher TM init function.
 *
 * \param tv       The cuda packet batcher TM ThreadVars instance.
 * \param initdata The initialization data needed by this cuda batcher TM.
 * \param data     Pointer to a ponter memory location that would be updated
 *                 with the newly created thread ctx instance.
 *
 * \retval TM_ECODE_OK     On success.
 * \retval TM_ECODE_FAILED On failure.
 */
TmEcode SCCudaPBThreadInit(ThreadVars *tv, void *initdata, void **data)
{
    SCCudaPBThreadCtx *tctx = NULL;

    if (initdata == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid argument.  initdata NULL "
                   "for the cuda batcher TM init thread function");
        return TM_ECODE_FAILED;
    }

    tctx = SCMalloc(sizeof(SCCudaPBThreadCtx));
    if (tctx == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    memset(tctx, 0, sizeof(SCCudaPBThreadCtx));

    /* the detection engine context.  We will need it to retrieve the sgh,
     * when we start receiving and batching the packets */
    tctx->de_ctx = initdata;

    /* the first packet buffer from the queue */
    tctx->curr_pb = (SCCudaPBPacketsBuffer *)SCDQDataDequeue(&data_queues[tmq_inq->id]);

    /* register new module */
    SCCudaHlRegisterModule("SC_CUDA_PACKET_BATCHER");

    *data = tctx;

    /* we will need the cuda packet batcher TM's inq for further use later.  Read
     * the comments associated with this var definition, for its use */
    tmq_batcher_inq = tv->inq;

    /* set the SIG_ALRM handler */
    SCCudaPBSetBatcherAlarmTimeHandler();

    /* Set the alarm time limit during which the batcher thread would
     * buffer packets */
    SCCudaPBResetBatcherAlarm();

    return TM_ECODE_OK;
}

/**
 * \brief Batches packets into the packets buffer.
 *
 * \param tv   Pointer to the ThreadVars instance, in this case the cuda packet
 *             batcher TM's TV instance.
 * \param p    Pointer the the packet to be buffered.
 * \param data Pointer the the batcher TM thread ctx.
 * \param pq   Pointer to the packetqueue.  We don't need this.
 *
 * \retval TM_ECODE_OK     On success.
 * \retval TM_ECODE_FAILED On failure.
 */
TmEcode SCCudaPBBatchPackets(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *post_pq)
{
#define ALIGN_UP(offset, alignment) \
    (offset) = ((offset) + (alignment) - 1) & ~((alignment) - 1)

    SCCudaPBThreadCtx *tctx = data;

    /* ah.  we have been signalled that we crossed the time limit within which we
     * need to buffer packets.  Let us queue the buffer to the GPU */
    if (queue_buffer) {
        SCLogDebug("Cuda packet buffer TIME limit exceeded.  Buffering packet "
                   "buffer and reseting the alarm");
        SCCudaPBQueueBuffer(tctx);
        SCCudaPBResetBatcherAlarm();
    }

    /* this is possible, since we are using a custom slot function that calls this
     * function, even if it receives no packet from the packet queue */
    if (p == NULL) {
        SCLogDebug("packet NULL inside Cuda batcher TM");
        return TM_ECODE_OK;
    }

    /* we set it for every incoming packet.  We will set this depending on whether
     * we end up buffering the packet or not */
    p->cuda_mpm_enabled = 0;

    /* packets that are too big are handled by the cpu */
    if (p->payload_len > SC_CUDA_PB_MAX_PAYLOAD_SIZE) {
        SCLogDebug("p->payload_len %"PRIu16" > %d, inspecting on the CPU.",
            p->payload_len, SC_CUDA_PB_MAX_PAYLOAD_SIZE);
        return TM_ECODE_OK;
    }

    /* the packets buffer */
    SCCudaPBPacketsBuffer *pb = (SCCudaPBPacketsBuffer *)tctx->curr_pb;
    /* the previous packet which has been buffered into the packets_buffer */
    SCCudaPBPacketDataForGPU *prev_buff_packet = NULL;
    /* holds the position in the packets_buffer where the curr packet would
     * be buffered in */
    SCCudaPBPacketDataForGPU *curr_packet = NULL;
    /* the sgh to which the incoming packet belongs */
    SigGroupHead *sgh = NULL;

    if (p->flow != NULL) {
        /* Get the stored sgh from the flow (if any). Make sure we're not using
         * the sgh for icmp error packets part of the same stream. */
        if (p->proto == p->flow->proto) { /* filter out icmp */
            if (p->flowflags & FLOW_PKT_TOSERVER && p->flow->flags & FLOW_SGH_TOSERVER) {
                sgh = p->flow->sgh_toserver;
            } else if (p->flowflags & FLOW_PKT_TOCLIENT && p->flow->flags & FLOW_SGH_TOCLIENT) {
                sgh = p->flow->sgh_toclient;
            }
        }
    }

    if (sgh == NULL) {
        /* get the signature group head to which this packet belongs.  If it belongs
         * to no sgh, we don't need to buffer this packet.
         * \todo Get rid of this, once we get the sgh from the flow */
        sgh = SCCudaPBGetSgh(tctx->de_ctx, p);
        if (sgh == NULL) {
            SCLogDebug("No SigGroupHead match for this packet");
            return TM_ECODE_OK;
        }
    }

    /* if the payload is less than the maximum content length in this sgh we
     * don't need to run the PM on this packet.  Chuck the packet out */
    if (sgh->mpm_content_maxlen > p->payload_len) {
        SCLogDebug("not mpm-inspecting as pkt payload is smaller than "
                   "the largest content length we need to match");
        return TM_ECODE_OK;
    }

    MpmCtx *mpm_ctx = NULL;
    if (p->proto == IPPROTO_TCP) {
        mpm_ctx = sgh->mpm_proto_tcp_ctx;
    } else if (p->proto == IPPROTO_UDP) {
        mpm_ctx = sgh->mpm_proto_udp_ctx;
    } else {
        mpm_ctx = sgh->mpm_proto_other_ctx;
    }

    /* if one of these conditions fail we don't have to run the mpm on this
     * packet.  Firstly if the payload_len is == 0, we don't have a payload
     * to match against.  Next if we don't have a mpm_context against this
     * sgh, indicating we don't have any patterns in this sgh, again we don't
     * have anything to run the PM against.  Finally if the flow doesn't want
     * to analyze packets for this flow, we can chuck this packet out as well */
    if ( !(p->payload_len > 0 && mpm_ctx != NULL &&
           !(p->flags & PKT_NOPAYLOAD_INSPECTION)) ) {
        SCLogDebug("Either p->payload_len <= 0 or mpm_ctx for the packet is NULL "
                   "or PKT_NOPAYLOAD_INSPECTION set for this packet");
        return TM_ECODE_OK;
    }

    /* the cuda b2g context */
    B2gCudaCtx *ctx = mpm_ctx->ctx;

    /* if we have a 1 byte search kernel set we don't buffer this packet for
     * cuda matching and instead run this non-cuda mpm function to be run on
     * the packet */
    if (ctx->Search == B2gCudaSearch1) {
        SCLogDebug("The packet has a one byte patterns.  run mpm "
                   "separately");
        return TM_ECODE_OK;
    }

#ifdef B2G_CUDA_SEARCH2
    /* if we have a 2 byte search kernel set we don't buffer this packet for
     * cuda matching and instead run this non-cuda mpm function to be run on the
     * packet */
    if (ctx->Search == B2gCudaSearch2) {
        SCLogDebug("The packet has two byte patterns.  run mpm "
                   "separately");
        return TM_ECODE_OK;
    }
#endif

    /* we have passed all the criterions for buffering the packet.  Set the
     * flag indicating that the packet goes through cuda mpm */
    p->cuda_mpm_enabled = 1;

    /* first packet to be buffered in */
    if (pb->nop_in_buffer == 0) {
        curr_packet = (SCCudaPBPacketDataForGPU *)pb->packets_buffer;

    /* buffer is not empty */
    } else {
        prev_buff_packet = (SCCudaPBPacketDataForGPU *)(pb->packets_buffer +
                                                        pb->packets_offset_buffer[pb->nop_in_buffer - 1]);
        curr_packet = (SCCudaPBPacketDataForGPU *)((uint8_t *)prev_buff_packet +
                                                   sizeof(SCCudaPBPacketDataForGPUNonPayload) +
                                                   prev_buff_packet->payload_len) ;
        int diff = (int)((uint8_t *)curr_packet - pb->packets_buffer);
        /* \todo Feel it is the wrong option taken by nvidia by setting CUdeviceptr
         * to unsigned int.  Keep this option for now.  We will get back to this
         * once nvidia responds to the filed bug */
        ALIGN_UP(diff, sizeof(CUdeviceptr));
        curr_packet = (SCCudaPBPacketDataForGPU *)(pb->packets_buffer + diff);
    }

    /* store the data in the packets_buffer for this packet, which would be passed
     * over to the GPU for processing */
    curr_packet->m = ((B2gCudaCtx *)(mpm_ctx->ctx))->m;
    curr_packet->table = ((B2gCudaCtx *)(mpm_ctx->ctx))->cuda_B2G;
    curr_packet->payload_len = p->payload_len;
    memcpy(curr_packet->payload, p->payload, p->payload_len);

    /* store the address of the packet just buffered at the same index.  The
     * dispatcher thread will need this address to communicate the results back
     * to the packet */
    pb->packets_address_buffer[pb->nop_in_buffer] = p;

    /* if it is the first packet to be buffered, the offset is 0.  If it is not,
     * then take the offset for the buffer from curr_packet */
    if (pb->nop_in_buffer == 0) {
        pb->packets_offset_buffer[pb->nop_in_buffer] = 0;
        pb->packets_payload_offset_buffer[pb->nop_in_buffer] = 0;
    } else {
        pb->packets_offset_buffer[pb->nop_in_buffer] = (uint8_t *)curr_packet - pb->packets_buffer;
        pb->packets_payload_offset_buffer[pb->nop_in_buffer] =
            pb->packets_payload_offset_buffer[pb->nop_in_buffer - 1] +
            prev_buff_packet->payload_len;
    }

    /* indicates the no of packets added so far into the buffer */
    pb->nop_in_buffer++;

    /* we have hit the threshhold for the total no of packets held in the buffer.
     * We will change this in the future, instead relying on the remaining space
     * left in the buffer or we have been informed that we have hit the time limit
     * to queue the buffer */
    if ( (pb->nop_in_buffer == buffer_packet_threshhold) || queue_buffer) {
        SCLogDebug("Either we have hit the threshold limit for packets(i.e. we "
                   "have %d packets limit) OR we have exceeded the buffering "
                   "time limit.  Buffering the packet buffer and reseting the "
                   "alarm.", buffer_packet_threshhold);
        SCCudaPBQueueBuffer(tctx);
        SCCudaPBResetBatcherAlarm();
    }

    return TM_ECODE_OK;
}

void SCCudaPBThreadExitStats(ThreadVars *tv, void *data)
{
    return;
}

/**
 * \brief The thread de-init function for the cuda packet batcher TM.
 *
 * \param tv   Pointer to the cuda packet batcher TM ThreadVars instance.
 * \param data Pointer the the Thread ctx for the cuda packet batcher TM.
 *
 * \retval TM_ECODE_OK     On success.
 * \retval TM_ECODE_FAILED On failure.  Although we won't be returning this here.
 */
TmEcode SCCudaPBThreadDeInit(ThreadVars *tv, void *data)
{
    SCCudaPBThreadCtx *tctx = data;

    if (tctx != NULL) {
        if (tctx->curr_pb != NULL) {
            if (SCCudaHlPushCudaContextFromModule("SC_CUDA_PACKET_BATCHER") == -1){
                SCLogError(SC_ERR_CUDA_HANDLER_ERROR,
                           "Failed to push cuda context from module");
            }

            SCCudaPBDeAllocSCCudaPBPacketsBuffer(tctx->curr_pb);
            tctx->curr_pb = NULL;

            if (SCCudaCtxPopCurrent(NULL) == -1){
                SCLogError(SC_ERR_CUDA_ERROR, "Failed to pop cuda context");
            }

            if (SCCudaHlDeRegisterModule("SC_CUDA_PACKET_BATCHER") == -1){
                SCLogError(SC_ERR_CUDA_HANDLER_ERROR, "Failed to deregister module");
            }
        }
        SCFree(tctx);
    }

    return TM_ECODE_OK;
}

/**
 * \brief Sets up the queues and buffers needed by the cuda batcher TM function.
 */
void SCCudaPBSetUpQueuesAndBuffers(void)
{
    /* the b2g dispatcher thread would have to use the reverse for incoming
     * and outgoing queues */
    char *inq_name = "cuda_batcher_mpm_inqueue";
    char *outq_name = "cuda_batcher_mpm_outqueue";
    int i = 0;

    /* set the incoming queue for the cuda_packet_batcher TM and the cuda B2g
     * dispatcher */
    tmq_inq = TmqGetQueueByName(inq_name);
    if (tmq_inq == NULL) {
        tmq_inq = TmqCreateQueue(inq_name);
        if (tmq_inq == NULL) {
            return;
        }
    }
    tmq_inq->reader_cnt++;
    tmq_inq->writer_cnt++;

    /* set the outgoing queue from the cuda_packet_batcher TM and the cuda B2g
     * dispatcher */
    tmq_outq = TmqGetQueueByName(outq_name);
    if (tmq_outq == NULL) {
        tmq_outq = TmqCreateQueue(outq_name);
        if (tmq_outq == NULL) {
            return;
        }
    }
    tmq_outq->reader_cnt++;
    tmq_outq->writer_cnt++;

    /* Register a new module to be used by the packet batcher to allocate
     * page-locked memory */
    SCCudaHlRegisterModule("SC_CUDA_PACKET_BATCHER");

    profile = SCCudaHlGetProfile("mpm");

    /* allocate the packet buffer */
    /* \todo need to work out the right no of packet buffers that we need to
     * queue.  I doubt we will need more than 4(as long as we don't run it on
     * low traffic line).  We don't want to get into the business of creating
     * new ones, when we run out of buffers, since malloc for a huge chunk
     * like this will take time.  We need to figure out a value based on
     * various other parameters like alarm time and buffer threshold value */
    for (i = 0; i < profile->packet_buffers; i++) {
        if (profile->page_locked) {
            SCLogDebug("Allocating \"%d\" page_locked cuda packet buffers",
                       profile->packet_buffers);
        } else {
            SCLogDebug("Allocating \"%d\" non-page_locked cuda packet buffers",
                       profile->packet_buffers);
        }

        SCCudaPBPacketsBuffer *pb = SCCudaPBAllocSCCudaPBPacketsBuffer();
        /* dump the buffer into the inqueue for this batcher TM.  the batcher
         * thread would be the first consumer for these buffers */
        SCDQDataEnqueue(&data_queues[tmq_inq->id], (SCDQGenericQData *)pb);
    }

    /* \todo This needs to be changed ASAP.  This can't exceed max_pending_packets.
     * Also we need to make this user configurable and allow dynamic updaes
     * based on live traffic */
    buffer_packet_threshhold = profile->packet_buffer_limit;

    return;
}

/**
 * \brief Clean up all the buffers queued in.  Need to write more on this.
 */
void SCCudaPBCleanUpQueuesAndBuffers(void)
{
    SCCudaPBPacketsBuffer *pb = NULL;
    SCDQDataQueue *dq = NULL;

    if (tmq_inq == NULL || tmq_outq == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENTS, "Invalid arguments.  tmq_inq or "
                   "tmq_outq NULL");
        return;
    }
    if (SCCudaHlPushCudaContextFromModule("SC_CUDA_PACKET_BATCHER") == -1){
        SCLogError(SC_ERR_CUDA_HANDLER_ERROR, "Could not push cuda context from module");
    }

    /* clean all the buffers present in the inq */
    dq = &data_queues[tmq_inq->id];
    SCMutexLock(&dq->mutex_q);
    while ( (pb = (SCCudaPBPacketsBuffer *)SCDQDataDequeue(dq)) != NULL) {
        if (pb->packets_buffer != NULL) {
            if (profile->page_locked) {
                if (SCCudaMemFreeHost(pb->packets_buffer) == -1) {
                    SCLogError(SC_ERR_CUDA_ERROR, "Error deallocating pagelocked memory: "
                               "packets_buffer");
                }
            } else {
                SCFree(pb->packets_buffer);
            }
        }
        if (pb->packets_offset_buffer != NULL) {
            if (profile->page_locked) {
                if (SCCudaMemFreeHost(pb->packets_offset_buffer) == -1) {
                    SCLogError(SC_ERR_CUDA_ERROR, "Error deallocating pagelocked memory: "
                               "packets_offset_buffer");
                }
            } else {
                SCFree(pb->packets_offset_buffer);
            }
        }
        if (pb->packets_payload_offset_buffer != NULL) {
            if (profile->page_locked) {
                if (SCCudaMemFreeHost(pb->packets_payload_offset_buffer) == -1) {
                    SCLogError(SC_ERR_CUDA_ERROR, "Error deallocating pagelocked memory: "
                               "packets_payload_offset_buffer");
                }
            } else {
                SCFree(pb->packets_payload_offset_buffer);
            }
        }

        SCFree(pb);
    }
    SCMutexUnlock(&dq->mutex_q);
    SCCondSignal(&dq->cond_q);

    /* clean all the buffers present in the outq */
    dq = &data_queues[tmq_outq->id];
    SCMutexLock(&dq->mutex_q);
    while ( (pb = (SCCudaPBPacketsBuffer *)SCDQDataDequeue(dq)) != NULL) {
        if (pb->packets_buffer != NULL) {
            if (SCCudaMemFreeHost(pb->packets_buffer) == -1) {
                SCLogError(SC_ERR_CUDA_ERROR, "Error deallocating pagelocked memory: "
                           "packets_buffer");
            }
        }
        if (pb->packets_offset_buffer != NULL) {
            if (SCCudaMemFreeHost(pb->packets_offset_buffer) == -1) {
                SCLogError(SC_ERR_CUDA_ERROR, "Error deallocating pagelocked memory: "
                           "packets_offset_buffer");
            }
        }
        if (pb->packets_payload_offset_buffer != NULL) {
            if (SCCudaMemFreeHost(pb->packets_payload_offset_buffer) == -1) {
                SCLogError(SC_ERR_CUDA_ERROR, "Error deallocating pagelocked memory: "
                           "packets_payload_offset_buffer");
            }
        }

        SCFree(pb);
    }
    if (SCCudaCtxPopCurrent(NULL) == -1){
        SCLogError(SC_ERR_CUDA_ERROR, "Could not pop cuda context");
    }
    SCMutexUnlock(&dq->mutex_q);
    SCCondSignal(&dq->cond_q);

    return;
}

/**
 * \brief Function used to set the packet threshhold limit in the packets buffer.
 *
 * \param threshhold_override The threshhold limit for the packets_buffer.
 */
void SCCudaPBSetBufferPacketThreshhold(uint32_t threshhold_override)
{
    buffer_packet_threshhold = threshhold_override;

    return;
}

/**
 * \brief Function used to set the profile for cuda packet batcher.  Used
 *        for unittests alone.
 */
void SCCudaPBSetProfile(char *profile_name)
{
    profile = SCCudaHlGetProfile("mpm");

    return;
}

/**
 * \brief Used to inform the cuda packet batcher that packet batching shouldn't
 *        be done anymore and set the flag to indicate this.  We also need to
 *        signal the cuda batcher data inq, in case it is waiting on the inq
 *        for a new free packet buffer.
 */
void SCCudaPBKillBatchingPackets(void)
{
    run_batcher = 0;
    SCDQDataQueue *dq = &data_queues[tmq_inq->id];
    SCCondSignal(&dq->cond_q);

    return;
}

void SCCudaPBRunningTests(int status)
{
    unittest_mode = status;
}

/***********************************Unittests**********************************/

#ifdef UNITTESTS

int SCCudaPBTest01(void)
{
#define ALIGN_UP(offset, alignment) \
    (offset) = ((offset) + (alignment) - 1) & ~((alignment) - 1)

    uint8_t raw_eth[] = {
        0x00, 0x25, 0x00, 0x9e, 0xfa, 0xfe, 0x00, 0x02,
        0xcf, 0x74, 0xfe, 0xe1, 0x08, 0x00, 0x45, 0x00,
        0x01, 0xcc, 0xcb, 0x91, 0x00, 0x00, 0x34, 0x06,
        0xdf, 0xa8, 0xd1, 0x55, 0xe3, 0x67, 0xc0, 0xa8,
        0x64, 0x8c, 0x00, 0x50, 0xc0, 0xb7, 0xd1, 0x11,
        0xed, 0x63, 0x81, 0xa9, 0x9a, 0x05, 0x80, 0x18,
        0x00, 0x75, 0x0a, 0xdd, 0x00, 0x00, 0x01, 0x01,
        0x08, 0x0a, 0x09, 0x8a, 0x06, 0xd0, 0x12, 0x21,
        0x2a, 0x3b, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31,
        0x2e, 0x31, 0x20, 0x33, 0x30, 0x32, 0x20, 0x46,
        0x6f, 0x75, 0x6e, 0x64, 0x0d, 0x0a, 0x4c, 0x6f,
        0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20,
        0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77,
        0x77, 0x77, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
        0x65, 0x2e, 0x65, 0x73, 0x2f, 0x0d, 0x0a, 0x43,
        0x61, 0x63, 0x68, 0x65, 0x2d, 0x43, 0x6f, 0x6e,
        0x74, 0x72, 0x6f, 0x6c, 0x3a, 0x20, 0x70, 0x72,
        0x69, 0x76, 0x61, 0x74, 0x65, 0x0d, 0x0a, 0x43,
        0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54,
        0x79, 0x70, 0x65, 0x3a, 0x20, 0x74, 0x65, 0x78,
        0x74, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x3b, 0x20,
        0x63, 0x68, 0x61, 0x72, 0x73, 0x65, 0x74, 0x3d,
        0x55, 0x54, 0x46, 0x2d, 0x38, 0x0d, 0x0a, 0x44,
        0x61, 0x74, 0x65, 0x3a, 0x20, 0x4d, 0x6f, 0x6e,
        0x2c, 0x20, 0x31, 0x34, 0x20, 0x53, 0x65, 0x70,
        0x20, 0x32, 0x30, 0x30, 0x39, 0x20, 0x30, 0x38,
        0x3a, 0x34, 0x38, 0x3a, 0x33, 0x31, 0x20, 0x47,
        0x4d, 0x54, 0x0d, 0x0a, 0x53, 0x65, 0x72, 0x76,
        0x65, 0x72, 0x3a, 0x20, 0x67, 0x77, 0x73, 0x0d,
        0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,
        0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a,
        0x20, 0x32, 0x31, 0x38, 0x0d, 0x0a, 0x0d, 0x0a,
        0x3c, 0x48, 0x54, 0x4d, 0x4c, 0x3e, 0x3c, 0x48,
        0x45, 0x41, 0x44, 0x3e, 0x3c, 0x6d, 0x65, 0x74,
        0x61, 0x20, 0x68, 0x74, 0x74, 0x70, 0x2d, 0x65,
        0x71, 0x75, 0x69, 0x76, 0x3d, 0x22, 0x63, 0x6f,
        0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x74, 0x79,
        0x70, 0x65, 0x22, 0x20, 0x63, 0x6f, 0x6e, 0x74,
        0x65, 0x6e, 0x74, 0x3d, 0x22, 0x74, 0x65, 0x78,
        0x74, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x3b, 0x63,
        0x68, 0x61, 0x72, 0x73, 0x65, 0x74, 0x3d, 0x75,
        0x74, 0x66, 0x2d, 0x38, 0x22, 0x3e, 0x0a, 0x3c,
        0x54, 0x49, 0x54, 0x4c, 0x45, 0x3e, 0x33, 0x30,
        0x32, 0x20, 0x4d, 0x6f, 0x76, 0x65, 0x64, 0x3c,
        0x2f, 0x54, 0x49, 0x54, 0x4c, 0x45, 0x3e, 0x3c,
        0x2f, 0x48, 0x45, 0x41, 0x44, 0x3e, 0x3c, 0x42,
        0x4f, 0x44, 0x59, 0x3e, 0x0a, 0x3c, 0x48, 0x31,
        0x3e, 0x33, 0x30, 0x32, 0x20, 0x4d, 0x6f, 0x76,
        0x65, 0x64, 0x3c, 0x2f, 0x48, 0x31, 0x3e, 0x0a,
        0x54, 0x68, 0x65, 0x20, 0x64, 0x6f, 0x63, 0x75,
        0x6d, 0x65, 0x6e, 0x74, 0x20, 0x68, 0x61, 0x73,
        0x20, 0x6d, 0x6f, 0x76, 0x65, 0x64, 0x0a, 0x3c,
        0x41, 0x20, 0x48, 0x52, 0x45, 0x46, 0x3d, 0x22,
        0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77,
        0x77, 0x77, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
        0x65, 0x2e, 0x65, 0x73, 0x2f, 0x22, 0x3e, 0x68,
        0x65, 0x72, 0x65, 0x3c, 0x2f, 0x41, 0x3e, 0x2e,
        0x0d, 0x0a, 0x3c, 0x2f, 0x42, 0x4f, 0x44, 0x59,
        0x3e, 0x3c, 0x2f, 0x48, 0x54, 0x4d, 0x4c, 0x3e,
        0x0d, 0x0a };

    int result = 0;
    SCCudaPBThreadCtx *tctx = NULL;

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (p == NULL)
    return 0;
    DecodeThreadVars dtv;
    ThreadVars tv;
    ThreadVars tv_cuda_PB;
    DetectEngineCtx *de_ctx = NULL;

    SCCudaPBPacketsBuffer *pb = NULL;
    SCCudaPBPacketDataForGPU *buff_packet = NULL;
    SCDQDataQueue *dq = NULL;

    uint32_t i = 0;

    char *strings[] = {"test_one",
                       "test_two",
                       "test_three",
                       "test_four",
                       "test_five",
                       "test_six",
                       "test_seven",
                       "test_eight",
                       "test_nine",
                       "test_ten"};

    uint32_t packets_payload_offset_buffer[sizeof(strings)/sizeof(char *)];
    memset(packets_payload_offset_buffer, 0, sizeof(packets_payload_offset_buffer));
    uint32_t packets_offset_buffer[sizeof(strings)/sizeof(char *)];
    memset(packets_offset_buffer, 0, sizeof(packets_offset_buffer));

    uint32_t packets_total_payload_len = 0;
    uint32_t packets_buffer_len = 0;

    for (i = 0; i < sizeof(strings)/sizeof(char *); i++) {
        packets_total_payload_len += strlen(strings[i]);
    }

    for (i = 1; i < sizeof(strings)/sizeof(char *); i++) {
        packets_payload_offset_buffer[i] = packets_payload_offset_buffer[i - 1] + strlen(strings[i - 1]);
        packets_offset_buffer[i] = packets_offset_buffer[i - 1] +
            sizeof(SCCudaPBPacketDataForGPUNonPayload) + strlen(strings[i - 1]);
        ALIGN_UP(packets_offset_buffer[i], sizeof(CUdeviceptr));
    }
    packets_buffer_len += packets_offset_buffer[(sizeof(strings)/sizeof(char *)) - 1] +
        sizeof(SCCudaPBPacketDataForGPUNonPayload) + strlen(strings[(sizeof(strings)/sizeof(char *)) - 1]);

    memset(p, 0, SIZE_OF_PACKET);
    p->pkt = (uint8_t *)(p + 1);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&tv_cuda_PB, 0, sizeof(ThreadVars));

    FlowInitConfig(FLOW_QUIET);
    DecodeEthernet(&tv, &dtv, p, raw_eth, sizeof(raw_eth), NULL);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = MPM_B2G_CUDA;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any (msg:\"Bamboo\"; "
                               "content:\"test\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("signature parsing failed\n");
        goto end;
    }
    SigGroupBuild(de_ctx);

    result = 1;

    SCCudaPBSetUpQueuesAndBuffers();
    dq = &data_queues[tmq_outq->id];
    result &= (dq->len == 0);
    dq = &data_queues[tmq_inq->id];
    result &= (dq->len == 10);
    SCCudaPBRunningTests(1);
    SCCudaPBThreadInit(&tv_cuda_PB, de_ctx, (void *)&tctx);
    SCCudaPBSetBufferPacketThreshhold(sizeof(strings)/sizeof(char *));

    p->payload = (uint8_t *)strings[0];
    p->payload_len = strlen(strings[0]);
    SCCudaPBBatchPackets(NULL, p, tctx, NULL, NULL);
    dq = &data_queues[tmq_outq->id];
    result &= (dq->len == 0);
    dq = &data_queues[tmq_inq->id];
    result &= (dq->len == 9);

    p->payload = (uint8_t *)strings[1];
    p->payload_len = strlen(strings[1]);
    SCCudaPBBatchPackets(NULL, p, tctx, NULL, NULL);
    dq = &data_queues[tmq_outq->id];
    result &= (dq->len == 0);
    dq = &data_queues[tmq_inq->id];
    result &= (dq->len == 9);

    p->payload = (uint8_t *)strings[2];
    p->payload_len = strlen(strings[2]);
    SCCudaPBBatchPackets(NULL, p, tctx, NULL, NULL);
    dq = &data_queues[tmq_outq->id];
    result &= (dq->len == 0);
    dq = &data_queues[tmq_inq->id];
    result &= (dq->len == 9);

    p->payload = (uint8_t *)strings[3];
    p->payload_len = strlen(strings[3]);
    SCCudaPBBatchPackets(NULL, p, tctx, NULL, NULL);
    dq = &data_queues[tmq_outq->id];
    result &= (dq->len == 0);
    dq = &data_queues[tmq_inq->id];
    result &= (dq->len == 9);

    p->payload = (uint8_t *)strings[4];
    p->payload_len = strlen(strings[4]);
    SCCudaPBBatchPackets(NULL, p, tctx, NULL, NULL);
    dq = &data_queues[tmq_outq->id];
    result &= (dq->len == 0);
    dq = &data_queues[tmq_inq->id];
    result &= (dq->len == 9);

    p->payload = (uint8_t *)strings[5];
    p->payload_len = strlen(strings[5]);
    SCCudaPBBatchPackets(NULL, p, tctx, NULL, NULL);
    dq = &data_queues[tmq_outq->id];
    result &= (dq->len == 0);
    dq = &data_queues[tmq_inq->id];
    result &= (dq->len == 9);

    p->payload = (uint8_t *)strings[6];
    p->payload_len = strlen(strings[6]);
    SCCudaPBBatchPackets(NULL, p, tctx, NULL, NULL);
    dq = &data_queues[tmq_outq->id];
    result &= (dq->len == 0);
    dq = &data_queues[tmq_inq->id];
    result &= (dq->len == 9);

    p->payload = (uint8_t *)strings[7];
    p->payload_len = strlen(strings[7]);
    SCCudaPBBatchPackets(NULL, p, tctx, NULL, NULL);
    dq = &data_queues[tmq_outq->id];
    result &= (dq->len == 0);
    dq = &data_queues[tmq_inq->id];
    result &= (dq->len == 9);

    p->payload = (uint8_t *)strings[8];
    p->payload_len = strlen(strings[8]);
    SCCudaPBBatchPackets(NULL, p, tctx, NULL, NULL);
    dq = &data_queues[tmq_outq->id];
    result &= (dq->len == 0);
    dq = &data_queues[tmq_inq->id];
    result &= (dq->len == 9);

    p->payload = (uint8_t *)strings[9];
    p->payload_len = strlen(strings[9]);
    SCCudaPBBatchPackets(NULL, p, tctx, NULL, NULL);
    dq = &data_queues[tmq_outq->id];
    result &= (dq->len == 1);
    dq = &data_queues[tmq_inq->id];
    result &= (dq->len == 8);

    dq = &data_queues[tmq_outq->id];
    pb = (SCCudaPBPacketsBuffer *)SCDQDataDequeue(dq);
    if (pb == NULL) {
        result = 0;
        goto end;
    }
    result &= (dq->len == 0);
    result &= (pb->nop_in_buffer == 10);
    if (result == 0)
        goto end;

    for (i = 0; i < pb->nop_in_buffer; i++) {
        buff_packet = (SCCudaPBPacketDataForGPU *)(pb->packets_buffer + pb->packets_offset_buffer[i]);
        result &= (strlen(strings[i]) == buff_packet->payload_len);
        result &= (memcmp(strings[i], buff_packet->payload, buff_packet->payload_len) == 0);
        if (result == 0)
            goto end;
        result &= (packets_payload_offset_buffer[i] == pb->packets_payload_offset_buffer[i]);
        result &= (packets_offset_buffer[i] == pb->packets_offset_buffer[i]);
    }
    result &= (packets_total_payload_len == pb->packets_total_payload_len);
    result &= (packets_buffer_len == pb->packets_buffer_len);

 end:
    SCCudaPBCleanUpQueuesAndBuffers();
    if (de_ctx) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    SCCudaPBThreadDeInit(NULL, tctx);
    SCFree(p);
    return result;
}

int SCCudaPBTest02(void)
{
    uint8_t raw_eth[] = {
        0x00, 0x25, 0x00, 0x9e, 0xfa, 0xfe, 0x00, 0x02,
        0xcf, 0x74, 0xfe, 0xe1, 0x08, 0x00, 0x45, 0x00,
        0x01, 0xcc, 0xcb, 0x91, 0x00, 0x00, 0x34, 0x06,
        0xdf, 0xa8, 0xd1, 0x55, 0xe3, 0x67, 0xc0, 0xa8,
        0x64, 0x8c, 0x00, 0x50, 0xc0, 0xb7, 0xd1, 0x11,
        0xed, 0x63, 0x81, 0xa9, 0x9a, 0x05, 0x80, 0x18,
        0x00, 0x75, 0x0a, 0xdd, 0x00, 0x00, 0x01, 0x01,
        0x08, 0x0a, 0x09, 0x8a, 0x06, 0xd0, 0x12, 0x21,
        0x2a, 0x3b, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31,
        0x2e, 0x31, 0x20, 0x33, 0x30, 0x32, 0x20, 0x46,
        0x6f, 0x75, 0x6e, 0x64, 0x0d, 0x0a, 0x4c, 0x6f,
        0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20,
        0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77,
        0x77, 0x77, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
        0x65, 0x2e, 0x65, 0x73, 0x2f, 0x0d, 0x0a, 0x43,
        0x61, 0x63, 0x68, 0x65, 0x2d, 0x43, 0x6f, 0x6e,
        0x74, 0x72, 0x6f, 0x6c, 0x3a, 0x20, 0x70, 0x72,
        0x69, 0x76, 0x61, 0x74, 0x65, 0x0d, 0x0a, 0x43,
        0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54,
        0x79, 0x70, 0x65, 0x3a, 0x20, 0x74, 0x65, 0x78,
        0x74, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x3b, 0x20,
        0x63, 0x68, 0x61, 0x72, 0x73, 0x65, 0x74, 0x3d,
        0x55, 0x54, 0x46, 0x2d, 0x38, 0x0d, 0x0a, 0x44,
        0x61, 0x74, 0x65, 0x3a, 0x20, 0x4d, 0x6f, 0x6e,
        0x2c, 0x20, 0x31, 0x34, 0x20, 0x53, 0x65, 0x70,
        0x20, 0x32, 0x30, 0x30, 0x39, 0x20, 0x30, 0x38,
        0x3a, 0x34, 0x38, 0x3a, 0x33, 0x31, 0x20, 0x47,
        0x4d, 0x54, 0x0d, 0x0a, 0x53, 0x65, 0x72, 0x76,
        0x65, 0x72, 0x3a, 0x20, 0x67, 0x77, 0x73, 0x0d,
        0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,
        0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a,
        0x20, 0x32, 0x31, 0x38, 0x0d, 0x0a, 0x0d, 0x0a,
        0x3c, 0x48, 0x54, 0x4d, 0x4c, 0x3e, 0x3c, 0x48,
        0x45, 0x41, 0x44, 0x3e, 0x3c, 0x6d, 0x65, 0x74,
        0x61, 0x20, 0x68, 0x74, 0x74, 0x70, 0x2d, 0x65,
        0x71, 0x75, 0x69, 0x76, 0x3d, 0x22, 0x63, 0x6f,
        0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x74, 0x79,
        0x70, 0x65, 0x22, 0x20, 0x63, 0x6f, 0x6e, 0x74,
        0x65, 0x6e, 0x74, 0x3d, 0x22, 0x74, 0x65, 0x78,
        0x74, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x3b, 0x63,
        0x68, 0x61, 0x72, 0x73, 0x65, 0x74, 0x3d, 0x75,
        0x74, 0x66, 0x2d, 0x38, 0x22, 0x3e, 0x0a, 0x3c,
        0x54, 0x49, 0x54, 0x4c, 0x45, 0x3e, 0x33, 0x30,
        0x32, 0x20, 0x4d, 0x6f, 0x76, 0x65, 0x64, 0x3c,
        0x2f, 0x54, 0x49, 0x54, 0x4c, 0x45, 0x3e, 0x3c,
        0x2f, 0x48, 0x45, 0x41, 0x44, 0x3e, 0x3c, 0x42,
        0x4f, 0x44, 0x59, 0x3e, 0x0a, 0x3c, 0x48, 0x31,
        0x3e, 0x33, 0x30, 0x32, 0x20, 0x4d, 0x6f, 0x76,
        0x65, 0x64, 0x3c, 0x2f, 0x48, 0x31, 0x3e, 0x0a,
        0x54, 0x68, 0x65, 0x20, 0x64, 0x6f, 0x63, 0x75,
        0x6d, 0x65, 0x6e, 0x74, 0x20, 0x68, 0x61, 0x73,
        0x20, 0x6d, 0x6f, 0x76, 0x65, 0x64, 0x0a, 0x3c,
        0x41, 0x20, 0x48, 0x52, 0x45, 0x46, 0x3d, 0x22,
        0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77,
        0x77, 0x77, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
        0x65, 0x2e, 0x65, 0x73, 0x2f, 0x22, 0x3e, 0x68,
        0x65, 0x72, 0x65, 0x3c, 0x2f, 0x41, 0x3e, 0x2e,
        0x0d, 0x0a, 0x3c, 0x2f, 0x42, 0x4f, 0x44, 0x59,
        0x3e, 0x3c, 0x2f, 0x48, 0x54, 0x4d, 0x4c, 0x3e,
        0x0d, 0x0a };

    int result = 0;
    const char *string = NULL;
    SCCudaPBThreadCtx *tctx = NULL;

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (p == NULL)
        return 0;
    DecodeThreadVars dtv;
    ThreadVars tv;
    ThreadVars tv_cuda_PB;
    DetectEngineCtx *de_ctx = NULL;

    SCCudaPBPacketsBuffer *pb = NULL;
    SCDQDataQueue *dq = NULL;


    memset(p, 0, SIZE_OF_PACKET);
    p->pkt = (uint8_t *)(p + 1);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&tv_cuda_PB, 0, sizeof(ThreadVars));

    FlowInitConfig(FLOW_QUIET);
    DecodeEthernet(&tv, &dtv, p, raw_eth, sizeof(raw_eth), NULL);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = MPM_B2G_CUDA;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any 5555 -> any any (msg:\"Bamboo\"; "
                               "content:\"test\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("signature parsing failed\n");
        goto end;
    }
    SigGroupBuild(de_ctx);

    SCCudaPBSetUpQueuesAndBuffers();
    dq = &data_queues[tmq_outq->id];
    result &= (dq->len == 0);
    dq = &data_queues[tmq_inq->id];
    result &= (dq->len == 10);
    SCCudaPBRunningTests(1);
    SCCudaPBThreadInit(&tv_cuda_PB, de_ctx, (void *)&tctx);

    result = 1;

    string = "test_one";
    p->payload = (uint8_t *)string;
    p->payload_len = strlen(string);
    SCCudaPBBatchPackets(NULL, p, tctx, NULL, NULL);
    dq = &data_queues[tmq_outq->id];
    result &= (dq->len == 0);
    dq = &data_queues[tmq_inq->id];
    result &= (dq->len == 9);

    pb = tctx->curr_pb;
    result &= (pb->nop_in_buffer == 0);

 end:
    SCCudaPBCleanUpQueuesAndBuffers();
    if (de_ctx) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    SCCudaPBThreadDeInit(NULL, tctx);
    SCFree(p);
    return result;
}

#endif /* UNITTESTS */

void SCCudaPBRegisterTests(void)
{

#ifdef UNITTESTS
    UtRegisterTest("SCCudaPBTest01", SCCudaPBTest01, 1);
    UtRegisterTest("SCCudaPBTest02", SCCudaPBTest02, 1);
#endif

    return;
}

#endif /* __SC_CUDA_SUPPORT__ */
