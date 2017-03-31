/* Copyright (C) 2007-2014 Open Information Security Foundation
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
 * \author Bao Lei <3862821@qq.com>
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "suricata-common.h" /* errno.h, string.h, etc. */
#include "tm-modules.h"      /* LogFileCtx */
#include "conf.h"            /* ConfNode, etc. */
#include "output.h"          /* DEFAULT_LOG_* */
#include "util-logopenfile.h"
#include "util-logopenfile-tile.h"
#include "util-logopenudp.h"
#define DEFAULT_DSTPORT "2928"
#define DEFAULT_DSTSERVER "127.0.0.1"


int SCLogOpenUDPSocket(ConfNode *udp_node, LogFileCtx *log_ctx)
{
	const char *udp_server = NULL;
    const char *udp_port = NULL;
	int sockfd=0;
	int i = 512;
	if (udp_node) {
        udp_server = ConfNodeLookupChildValue(udp_node, "server");
        udp_port =  ConfNodeLookupChildValue(udp_node, "port");
    }
	if(!udp_server)
		udp_server=DEFAULT_DSTSERVER;
	if(!udp_port)
		udp_port=DEFAULT_DSTPORT;
    SCLogNotice("Write log to socket \"%s:%s\"", udp_server,udp_port);
	log_ctx->udp_server=SCStrdup(udp_server);
	log_ctx->udp_port=SCStrdup(udp_port);
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd<0)
		return -1;
	bzero(&log_ctx->udp_serveraddr, sizeof(struct sockaddr_in));
	log_ctx->udp_serveraddr.sin_family = AF_INET;
	log_ctx->udp_serveraddr.sin_port = htons(atoi(udp_port));
	log_ctx->udp_serveraddr.sin_addr.s_addr = inet_addr(udp_server);
	setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,(void *)&i,sizeof(i));
	if(sockfd<0)
		return -1;
	log_ctx->udp_fd=sockfd;
	log_ctx->is_sock=1;
	log_ctx->Write=SCLogUDPSocketWrite;
	log_ctx->Close=SCLogUDPSocketClose;
	return sockfd;
}
int SCLogUDPSocketReconnect(LogFileCtx *log_ctx)
{
	struct timeval tv;
    uint64_t now;
    gettimeofday(&tv, NULL);
    now = (uint64_t)tv.tv_sec * 1000;
    now += tv.tv_usec / 1000;           /* msec resolution */
    if (log_ctx->reconn_timer != 0 &&
            (now - log_ctx->reconn_timer) < LOGFILE_RECONN_MIN_TIME) {
        /* Don't bother to try reconnecting too often. */
        return 0;
    }
    log_ctx->reconn_timer = now;
	//may be no use reconnect.
	return 1;
}
int SCLogUDPSocketWrite(const char *buffer,int buffer_len,LogFileCtx *log_ctx)
{
	int ret=-1;
	if(log_ctx->udp_fd>0)
	ret=sendto(log_ctx->udp_fd,buffer,buffer_len,0,(struct sockaddr *)&log_ctx->udp_serveraddr,sizeof(log_ctx->udp_serveraddr));
	return ret;
}
void SCLogUDPSocketClose(LogFileCtx *log_ctx)
{
	if(log_ctx->udp_fd>0)
		close(log_ctx->udp_fd);
	log_ctx->udp_fd=0;
}
