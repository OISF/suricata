/* Copyright (C) 2007-2017 Open Information Security Foundation
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
 * \author Dave Remien <dave.remien@gmail.com>
 *
 *  Use shared memseg to receive packet timing info from Suricata, (mods in
 *  source-nfq.c), and process counts into 10 usec buckets (0 to 4999 usec).
 *  Suricata only records this info if this program is attached to the shared
 *  memseg, to minimize CPU utilization in Suricata.
 *  This program displays the bucket counts for each time segment (0-9 usec,
 *  10-19 usec, etc.).
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>




#define SHM_SIZE 65536  /* make it a 64K shared memory segment */

struct  memseg {
    int reader_attached;
    struct {
	    struct timeval pktrcvd;
	    struct timeval pktsent;
	    uint32_t id;
	} pkttimes[1024];
    uint32_t updated;
    uint64_t buckets10us[500];
    double boxcar;
    int shmid;
} *m;


int main(argc, argv)
	int	argc;
	char	*argv[];
{

    int shmid;
	long n, i, j;
	int mode;
	int nperline;
	int ntimes;

	nperline = 8;
	if (argc > 1)nperline = atoi(argv[1]);
	/*  get the handle of the segment: */
	if ((shmid = shmget(0xdeadbeef, SHM_SIZE, 0644)) == -1) {
	    perror("shmget");
		exit(1);
	}

	/* attach to the segment to get a pointer to it: */
    m = shmat(shmid, (void *)0, 0);
    if ((long)m == (-1)) {
	    perror("shmat");
	    exit(1);
    }


	for (i = 0; i < 500; i++){
	    if(m->buckets10us[i])printf ("%5ld usec # = %7ld  ", i * 10, 
                  m->buckets10us[i]);
	    if (!(i % nperline))printf("\n");
	}
	printf("\n");
}
