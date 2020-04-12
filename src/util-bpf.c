/* Copyright (C) 2018 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 */


#include "suricata-common.h"
#include "config.h"
#include "suricata.h"
#include "util-bpf.h"

#if !defined __OpenBSD__

/** protect bpf filter build, as it is not thread safe */
static SCMutex bpf_set_filter_lock = SCMUTEX_INITIALIZER;

void SCBPFFree(struct bpf_program *program)
{
    if (program)
        pcap_freecode(program);
}

int SCBPFCompile(int snaplen_arg, int linktype_arg, struct bpf_program *program,
                 const char *buf,
                 int optimize, uint32_t mask,
                 char *errbuf, size_t errbuf_len)
{
    pcap_t *p;
    int ret;

    p = pcap_open_dead(linktype_arg, snaplen_arg);
    if (p == NULL)
        return (-1);

    SCMutexLock(&bpf_set_filter_lock);
    ret = pcap_compile(p, program, buf, optimize, mask);
    if (ret == -1) {
        if (errbuf) {
            snprintf(errbuf, errbuf_len, "%s", pcap_geterr(p));
        }
        pcap_close(p);
        SCMutexUnlock(&bpf_set_filter_lock);
        return (-1);
    }
    pcap_close(p);
    SCMutexUnlock(&bpf_set_filter_lock);

    if (program->bf_insns == NULL) {
        if (errbuf) {
            snprintf(errbuf, errbuf_len, "Filter badly setup");
        }
        SCBPFFree(program);
        return (-1);
    }

    return (ret);
}

#endif /* Not __OpenBSD__ */

/**
 * \brief Set the BPF based on the provided BPF file.
 *
 * Parses a BPF from the specified file. Note that in case of success
 * the caller is the one responsible for freeing the allocated BPF.
 * 
 * \param vptr Pointer that will be set to the BPF value.
 *
 * \retval TM_ECODE_OK will be returned if the BPF is parsed, otherwise
 *   TM_ECODE_FAILED will be returned.
 */
static int ParseBpfFromFile(const char *filename, const char **vptr)
{
    char *bpf_filter = NULL;
    char *bpf_comment_tmp = NULL;
    char *bpf_comment_start =  NULL;
    uint32_t bpf_len = 0;
#ifdef OS_WIN32
    struct _stat st;
#else
    struct stat st;
#endif /* OS_WIN32 */
    FILE *fp = NULL;
    size_t nm = 0;

    if (EngineModeIsIPS()) {
        SCLogError(SC_ERR_NOT_SUPPORTED,
                   "BPF not available in IPS mode."
                   " Use firewall filtering if possible.");
        return TM_ECODE_FAILED;
    }

#ifdef OS_WIN32
    if(_stat(filename, &st) != 0) {
#else
    if(stat(filename, &st) != 0) {
#endif /* OS_WIN32 */
        SCLogError(SC_ERR_FOPEN, "Failed to stat file %s", filename);
        return TM_ECODE_FAILED;
    }
    bpf_len = st.st_size + 1;

    // coverity[toctou : FALSE]
    fp = fopen(filename,"r");
    if (fp == NULL) {
        SCLogError(SC_ERR_FOPEN, "Failed to open file %s", filename);
        return TM_ECODE_FAILED;
    }

    bpf_filter = SCMalloc(bpf_len * sizeof(char));
    if (unlikely(bpf_filter == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate buffer for BPF in file %s", filename);
        return TM_ECODE_FAILED;
    }
    memset(bpf_filter, 0x00, bpf_len);

    nm = fread(bpf_filter, 1, bpf_len - 1, fp);
    if ((ferror(fp) != 0) || (nm != (bpf_len - 1))) {
        SCLogError(SC_ERR_BPF, "Failed to read complete BPF file %s", filename);
        SCFree(bpf_filter);
        fclose(fp);
        return TM_ECODE_FAILED;
    }
    fclose(fp);
    bpf_filter[nm] = '\0';

    if(strlen(bpf_filter) > 0) {
        /*replace comments with space*/
        bpf_comment_start = bpf_filter;
        while((bpf_comment_tmp = strchr(bpf_comment_start, '#')) != NULL) {
            while((*bpf_comment_tmp !='\0') &&
                (*bpf_comment_tmp != '\r') && (*bpf_comment_tmp != '\n'))
            {
                *bpf_comment_tmp++ = ' ';
            }
            bpf_comment_start = bpf_comment_tmp;
        }
        /*remove remaining '\r' and '\n' */
        while((bpf_comment_tmp = strchr(bpf_filter, '\r')) != NULL) {
            *bpf_comment_tmp = ' ';
        }
        while((bpf_comment_tmp = strchr(bpf_filter, '\n')) != NULL) {
            *bpf_comment_tmp = ' ';
        }
        /* cut trailing spaces */
        while (strlen(bpf_filter) > 0 &&
                bpf_filter[strlen(bpf_filter)-1] == ' ')
        {
            bpf_filter[strlen(bpf_filter)-1] = '\0';
        }

        if (strlen(bpf_filter) > 0) {
            *vptr = bpf_filter;
        }
        else {
            SCLogError(SC_ERR_BPF, "Extracted BPF from %s is empty", filename);
            SCFree(bpf_filter);
            return TM_ECODE_FAILED;
        }
    }
    else {
        SCLogError(SC_ERR_BPF, "Empty BPF file provided %s", filename);
        SCFree(bpf_filter);
        return TM_ECODE_FAILED;
    }

    return TM_ECODE_OK;
}

/**
 * \brief Set the BPF based on the provided command line.
 *
 * Sets the "bpf-filter" configuration option with the command line provided
 * BPF.
 * 
 * \param argc Number of command line arguments.
 * \param argv Actual command line arguments.
 *
 * \retval TM_ECODE_OK will be returned if the BPF is set, otherwise
 *   TM_ECODE_FAILED will be returned.
 */
int SetBpfString(int argc, char *argv[])
{
    char *bpf_filter = NULL;
    uint32_t bpf_len = 0;
    int tmpindex = 0;

    /* attempt to parse remaining args as bpf */
    tmpindex = argc;
    while(argv[tmpindex] != NULL) {
        bpf_len+=strlen(argv[tmpindex]) + 1;
        tmpindex++;
    }

    if (bpf_len == 0)
        return TM_ECODE_OK;

    if (EngineModeIsIPS()) {
        SCLogError(SC_ERR_NOT_SUPPORTED,
                   "BPF not available in IPS mode."
                   " Use firewall filtering if possible.");
        return TM_ECODE_FAILED;
    }

    bpf_filter = SCMalloc(bpf_len);
    if (unlikely(bpf_filter == NULL))
        return TM_ECODE_OK;
    memset(bpf_filter, 0x00, bpf_len);

    tmpindex = optind;
    while(argv[tmpindex] != NULL) {
        strlcat(bpf_filter, argv[tmpindex],bpf_len);
        if(argv[tmpindex + 1] != NULL) {
            strlcat(bpf_filter," ", bpf_len);
        }
        tmpindex++;
    }

    if(strlen(bpf_filter) > 0) {
        if (ConfSetFinal("bpf-filter", bpf_filter) != 1) {
            SCLogError(SC_ERR_FATAL, "Failed to set BPF.");
            SCFree(bpf_filter);
            return TM_ECODE_FAILED;
        }
    }
    SCFree(bpf_filter);

    return TM_ECODE_OK;
}

/**
 * \brief Set the BPF based on the specified file.
 *
 * Make use of the ParseBpfFromFile function to parse the BPF and sets
 * the "bpf-filter" configuration option with the result.
 * 
 * \param filename Name of the file containing the BPF.
 *
 * \retval TM_ECODE_OK will be returned if the BPF is parsed, otherwise
 *   TM_ECODE_FAILED will be returned.
 */
int SetBpfStringFromFile(const char *filename)
{
    const char *bpf_filter = NULL;

    int ret = ParseBpfFromFile(filename, &bpf_filter);

    if (ret == TM_ECODE_OK) {
        if(ConfSetFinal("bpf-filter", bpf_filter) != 1) {
            SCLogError(SC_ERR_FOPEN, "ERROR: Failed to set the BPF!");
            ret = TM_ECODE_FAILED;
        }
    }
    
    if (bpf_filter != NULL) {
        SCFree((char *)bpf_filter);
    }

    return ret;
}

/**
 * \brief Parse the BPF from the Suricata configuration file.
 *
 * This function parses the "bpf-filter" configuration option and
 * supports files as well as BPF expressions. Two notes, first the command
 * line value has precedence, second the pointer retuned in vptr needs to be
 * freed by the caller in case of success.
 * 
 * \param vptr Pointer that will be set to the configuration value parameter.
 *
 * \retval 1 will be returned if the BPF is parsed, otherwise
 *   0 will be returned.
 */
int ParseBpfConfig(ConfNode *if_root, const char **vptr)
{
    ConfNode *if_default = NULL;
    const char *bpf_filter = NULL;
    const char *bpf_tmp = NULL;
#ifdef OS_WIN32
    struct _stat st;
#else
    struct stat st;
#endif /* OS_WIN32 */

    if (ConfGet("bpf-filter", &bpf_filter) == 1) {
        if (strlen(bpf_filter) > 0) {
            *vptr = SCStrdup(bpf_filter);

            if (unlikely(*vptr == NULL)) {
                SCLogError(SC_ERR_MEM_ALLOC,
                           "Can't allocate BPF string");
            } else {
                SCLogDebug("Going to use command-line provided BPF %s",
                           bpf_filter);

                return 1;
            }
        }
    } else {
        if (ConfGetChildValueWithDefault(if_root, if_default, "bpf-filter", &bpf_tmp) == 1) {
            if (strlen(bpf_tmp) > 0) {
#ifdef OS_WIN32
                if (_stat(bpf_tmp, &st) == 0) {
#else
                if (stat(bpf_tmp, &st) == 0) {
#endif /* OS_WIN32 */
                    if (ParseBpfFromFile(bpf_tmp, &bpf_filter) == TM_ECODE_FAILED) {
                        return 0;
                    }
                }
                else {
                    bpf_filter = bpf_tmp;
                }

                *vptr = SCStrdup(bpf_filter);

                if (unlikely(*vptr == NULL)) {
                    SCLogError(SC_ERR_MEM_ALLOC,
                               "Can't allocate BPF string");
                } else {
                    SCLogDebug("Going to use BPF %s",
                               bpf_filter);

                    return 1;
                }
            }
        }
    }

    return 0;
}
