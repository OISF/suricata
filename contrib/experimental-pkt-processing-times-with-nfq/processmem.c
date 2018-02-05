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
 *  source-nfq.[ch]), and process counts into 10 usec buckets (0 to 4999 usec).
 *  Suricata only records this info if this program is attached to the shared
 *  memseg, to minimize CPU utilization in Suricata.
 *
 */

#include <unistd.h>
#include <curses.h>
#include <signal.h>
#include <time.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>




#define BOX 100.0
#define SHMID 0xdeadbeef
#define SHM_SIZE 65536  /* make it a 64K shared memory segment */





struct {
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
    uint32_t pmod;
    int ntimes;
    uint64_t delta;
    uint32_t lastpktid;



    /*   create or map the segment:  */
    if ((shmid = shmget(SHMID, SHM_SIZE, 0644)) == -1) {
 	    perror("shmget");
 	    exit(1);
    }

    /* attach to the segment to get a pointer to it: */
    m = shmat(shmid, (void *)0, 0);
    if ((long)m == (-1)) {
 	    perror("shmat");
 	    exit(1);
    }

    m->reader_attached = 1;
    mode = 0;
    char c;
    extern	void die();
    ntimes = 1;

    signal(SIGHUP, die);
    signal(SIGINT, die);
    signal(SIGQUIT, die);
    signal(SIGTERM, die);

    initscr();
    cbreak();
    noecho();
    nodelay(stdscr, TRUE);
    /*halfdelay(1); */
    clear();

    while (TRUE) {
 	    if (m->updated){
 	        lastpktid = m->updated;
			pmod = lastpktid % 1024;
			delta =
			        ((((m->pkttimes[pmod].pktsent.tv_sec -
						m->pkttimes[pmod].pktrcvd.tv_sec) * 1000000) +
					  (m->pkttimes[pmod].pktsent.tv_usec - 
					    m->pkttimes[pmod].pktrcvd.tv_usec)));
			m->boxcar = (m->boxcar - (m->boxcar / BOX) + (double)delta / BOX);
			if(delta < 4990)m->buckets10us[(delta / 10)]++;
			else m->buckets10us[499]++;
			m->updated = 0;
		}
		if ( !(ntimes++ % 100000)) {
		    c = getch();
			if(c == 81 || c == 113){
			    die();
			}else if(c == 67 || c == 99 || c == 12){
			    initscr();
				cbreak();
				noecho();
				nodelay(stdscr, TRUE);
				clear();
			}else if(c == 120){
			    move(0, 0);
				printw("pktid %d boxcar avg of last %d pkts =  %10.1f usec mode = %d",
					   lastpktid, (int)BOX, m->boxcar, mode % 2);
				addch('\n');
				clrtoeol();
				clrtobot();
				move(LINES-1, 0);
				printw(" Press 'h' for help.");
				refresh();
			}else if(c == 109){
			    mode++;
			}else if(c == 122){
			    for (i = 0; i < 500; i++)m->buckets10us[i] = 0;
			}else if(c == 104 || c == 72){   // Help!
			    move (5, 0);
				printw(" Help: \n");
				printw(" c or C - clears screen, refreshes\n");
				printw(" m - Mode change (dead loop (0) or with sched yield (1) - toggle)\n");
				printw(" z - zero the 500 buckets (10 us per bucket)\n");
				printw(" x - update the pktid / avg / mode line\n");
				printw(" w - warranty\n");
				printw(" l - license info\n");
				printw(" q or Q - quit, detaching from memseg and stopping delta time collection for pkts\n");
				clrtobot();
				refresh();
			}else if(c == 108){
			    move (5, 0);
				printw(" License and redistribution:\n\n");
				printw(" See LICENSE and COPYING files in the top level suricata directory.\n");
				clrtoeol();
				clrtobot();
				refresh();
			}else if(c == 119){
			    move (5, 0);
				printw(" Warranty: \n\n");
				printw(" processmem version 1, Copyright (C) 2017 Dave Remien\n");
				printw(" processmem comes with ABSOLUTELY NO WARRANTY; for details type 'l'.\n");
				printw(" This is free software, and you are welcome to redistribute it\n");
				printw(" under certain conditions; type 'l' for details.\n");
				clrtoeol();
				clrtobot();
				refresh();
			}
		}
	    if(mode % 2) usleep(0);
	}
}

void die()
{
    m->reader_attached = 0;
    move(LINES-1, 0);
    clrtoeol();
    refresh();
    endwin();
    fprintf(stderr, " Time to die...\n");
    exit(0);
}
