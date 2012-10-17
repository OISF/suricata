/* Copyright (C) 2011 Open Information Security Foundation
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
 *  \author nPulse Technologies, LLC.
 *  \author Matt Keeler <mk@npulsetech.com>
 */

#include "suricata-common.h"
#include "tm-threads.h"
#include "conf.h"
#include "runmodes.h"
#include "runmode-napatech.h"
#include "log-httplog.h"
#include "output.h"

#include "alert-fastlog.h"
#include "alert-prelude.h"
#include "alert-unified2-alert.h"
#include "alert-debuglog.h"

#include "util-debug.h"
#include "util-time.h"
#include "util-cpu.h"
#include "util-affinity.h"

#include "runmode-napatech-3gd.h"

static const char *default_mode = NULL;

const char *RunModeNapatech3GDGetDefaultMode(void)
{
    return default_mode;
}

void RunModeNapatech3GDRegister(void)
{
    SCLogInfo("RunModeNapatech3GDRegister called\n");
#ifdef HAVE_NAPATECH_3GD
    default_mode = "auto";
    RunModeRegisterNewRunMode(RUNMODE_NAPATECH_3GD, "auto",
            "Multi threaded Napatech mode",
            RunModeNapatech3GDAuto);
    return;
#endif
}

int RunModeNapatech3GDAuto(DetectEngineCtx *de_ctx) {
    SCEnter();
#ifdef HAVE_NAPATECH_3GD
    intmax_t num_stream_threads;
    intmax_t num_detect_threads;
    intmax_t num_output_threads;
    const char *thread_group_capture = "Napatech3GDStreamCapture";
    const char *thread_group_detect = "Detect";

    char tname [128];
    char *thread_name = NULL;
    char *queue_name = NULL;
    uint16_t cpu, ncpus;
    uint8_t stream, thread;
    int status;
    char errbuf[100];

    RunModeInitialize ();
    
    if (ConfGetInt("napatech3gd.streams", &num_stream_threads) == 0) {
        SCLogError(SC_ERR_RUNMODE, "Failed retrieving napatech3gd.streams from Conf");
        exit(EXIT_FAILURE);
    }
    if (ConfGetInt("napatech3gd.detect-threads-per-stream", &num_detect_threads) == 0) {
        SCLogError(SC_ERR_RUNMODE, "Failed retrieving napatech3gd.detect-threads from Conf");
        exit(EXIT_FAILURE);
    }
    if (ConfGetInt("napatech3gd.output-threads", &num_output_threads) == 0) {
        SCLogError(SC_ERR_RUNMODE, "Failed retrieving napatech3gd.output-threads from Conf");
        exit(EXIT_FAILURE);
    }
    
    if (num_stream_threads < 1) {
        SCLogError(SC_ERR_RUNMODE, "Number of configured streams is less than 1");
        exit(EXIT_FAILURE);
    }
    if (num_detect_threads < 1) {
        SCLogError(SC_ERR_RUNMODE, "Number of configured detection threads is less than 1");
        exit(EXIT_FAILURE);
    }
    if (num_output_threads < 1) {
        SCLogError(SC_ERR_RUNMODE, "Number of configured output threads is less than 1");
        exit(EXIT_FAILURE);
    }
    
    TimeModeSetLive();

    /* Initialize the 3GD API and check version compatibility */
    if ((status = NT_Init(NTAPI_VERSION)) != NT_SUCCESS) {
        NT_ExplainError(status, errbuf, sizeof(errbuf));
        SCLogError(SC_ERR_NAPATECH_3GD_INIT_FAILED ,"NT_Init failed. Code 0x%X = %s\n", status, errbuf);
        exit(EXIT_FAILURE);
    }
    
    /* Available cpus */
    ncpus = UtilCpuGetNumProcessorsOnline();
        
    /* start with cpu 1 so that if we're creating an odd number of detect
     * threads we're not creating the most on CPU0. */
    if (ncpus > 0)
        cpu = 1; 
    
    /* Spawn the receiving threads - these communicate with the napatech 3gd driver */
    for (stream=0; stream < num_stream_threads; stream++, cpu=(cpu +1) % ncpus) {
        snprintf(tname, sizeof(tname),"NT3GDStream%"PRIu16, stream);
        thread_name = SCStrdup(tname);

        snprintf(tname, sizeof(tname),"nt3gd-q%"PRIu16,stream);
        queue_name = SCStrdup(tname);

        /* create the threads */
        ThreadVars *tv_n3gd_capture =
            TmThreadCreatePacketHandler(thread_name,
                                        "packetpool", "packetpool",
                                        queue_name, "simple",
                                        "pktacqloop");
                
        if (tv_n3gd_capture == NULL) {
            fprintf(stderr, "ERROR: TmThreadsCreate failed\n");
            exit(EXIT_FAILURE);
        }

        TmModule *tm_module = TmModuleGetByName("Napatech3GDStream");
        if (tm_module == NULL) {
            fprintf(stderr, "ERROR: TmModuleGetByName failed for Napatech3GDStream\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend (tv_n3gd_capture, tm_module, stream);

        tm_module = TmModuleGetByName("Napatech3GDDecode");
        if (tm_module == NULL) {
            fprintf(stderr, "ERROR: TmModuleGetByName failed for Napatech3GDDecode\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_n3gd_capture, tm_module, NULL);

        if (threading_set_cpu_affinity) {
            TmThreadSetCPUAffinity(tv_n3gd_capture, cpu);
        }

        tm_module = TmModuleGetByName("StreamTcp");
        if (tm_module == NULL) {
            fprintf(stderr, "ERROR: TmModuleGetByName StreamTcp failed\n");
            exit(EXIT_FAILURE);
        }
        TmSlotSetFuncAppend(tv_n3gd_capture, tm_module, NULL);
        
        /* Set the thread group name */
        char *tgroup = SCStrdup(thread_group_capture);
        if (tgroup == NULL) {
            fprintf(stderr, "Error allocating memory\n");
            exit(EXIT_FAILURE);
        }
        tv_n3gd_capture->thread_group_name = tgroup;
        
        if (TmThreadSpawn(tv_n3gd_capture) != TM_ECODE_OK) {
            fprintf(stderr, "ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }
        
        /* Setup Detect Threads */
        for(thread = 0; thread < num_detect_threads; thread++) {
            snprintf(tname, sizeof(tname), "Detect%"PRIu16":%"PRIu16, stream, thread);
            thread_name = SCStrdup(tname);
             
            ThreadVars *tv_detect = 
                TmThreadCreatePacketHandler(thread_name,
                                            queue_name, "simple",
                                            "alert-queue", "simple",
                                            "1slot");
            
            if (tv_detect == NULL) {
                fprintf(stderr, "ERROR: TmThreadsCreate failed\n");
                exit(EXIT_FAILURE);
            }
            
            TmModule *tm_module = TmModuleGetByName("Detect");
            if (tm_module == NULL) {
                fprintf(stderr, "ERROR: TmModuleGetByName Detect failed\n");
                exit(EXIT_FAILURE);
            }
            TmSlotSetFuncAppend(tv_detect, tm_module, (void *)de_ctx);
            
            TmThreadSetCPU(tv_detect, DETECT_CPU_SET);
            
            /* Set the thread group name */
            char *tgroup = SCStrdup(thread_group_detect);
            if (tgroup == NULL) {
                fprintf(stderr, "Error allocating memory\n");
                exit(EXIT_FAILURE);
            }
            tv_detect->thread_group_name = tgroup;
            
            /* Spawn the thread */
            if (TmThreadSpawn(tv_detect) != TM_ECODE_OK) {
                fprintf(stderr, "ERROR: TmThreadSpawn failed\n");
                exit(EXIT_FAILURE);
            }
        }
        
    }
    
    if(ncpus > 0)
        cpu = 1;
        
    
    for(thread = 0; thread < num_output_threads; thread++) {
        /* Setup the Ouput Thread */
        ThreadVars *tv_output =
            TmThreadCreatePacketHandler("Output",
                                        "alert-queue", "simple",
                                        "packetpool", "packetpool",
                                        "varslot");
        if (tv_output == NULL) {
            fprintf(stderr, "ERROR: TmThreadCreatePacketHandler for Output failed\n");
            exit(EXIT_FAILURE);
        }                                
        SetupOutputs(tv_output);
        TmThreadSetCPU(tv_output, OUTPUT_CPU_SET);
        
        char *tgroup = SCStrdup("Outputs");
        if (tgroup == NULL) {
            fprintf(stderr, "Error allocating memory\n");
            exit(EXIT_FAILURE);
        }
        tv_output->thread_group_name = tgroup;
        
        if (TmThreadSpawn(tv_output) != TM_ECODE_OK) {
            fprintf(stderr, "ERROR: TmThreadSpawn failed\n");
            exit(EXIT_FAILURE);
        }
    }
    
#endif    
    return 0;   
}


