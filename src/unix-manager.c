/* Copyright (C) 2012 Open Information Security Foundation
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
#include "unix-manager.h"
#include "tm-threads.h"
#include "runmodes.h"
#include "conf.h"

#include "util-privs.h"
#include "util-debug.h"

#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef BUILD_UNIX_SOCKET
#include <jansson.h>

#define SOCKET_PATH LOCAL_STATE_DIR "/run/suricata/"
#define SOCKET_FILENAME "suricata-command.socket"
#define SOCKET_TARGET SOCKET_PATH SOCKET_FILENAME

typedef struct UnixCommand_ {
    time_t start_timestamp;
    int socket;
    int client;
    struct sockaddr_un client_addr;
    int select_max;
    fd_set select_set;
} UnixCommand;


/**
 * \brief Create a command unix socket on system
 *
 * \retval 0 in case of error, 1 in case of success
 */
int UnixNew(UnixCommand * this)
{
    struct sockaddr_un addr;
    int len;
    int ret;
    int on = 1;

    this->start_timestamp = time(NULL);
    this->socket = -1;
    this->client = -1;
    this->select_max = 0;

    /* Create socket dir */
    ret = mkdir(SOCKET_PATH, S_IRWXU|S_IXGRP|S_IRGRP);
    if ( ret != 0 ) {
        int err = errno;
        if (err != EEXIST) {
            SCLogError(SC_ERR_OPENING_FILE,
                    "Cannot create socket directory %s: %s", SOCKET_PATH, strerror(err));
            return 0;
        }
    }

    /* Remove socket file */
    (void) unlink(SOCKET_TARGET);

    /* set address */
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_TARGET, sizeof(addr.sun_path));
    addr.sun_path[sizeof(addr.sun_path) - 1] = 0;
    len = strlen(addr.sun_path) + sizeof(addr.sun_family);

    /* create socket */
    this->socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (this->socket == -1) {
        SCLogWarning(SC_ERR_OPENING_FILE,
                     "Unix Socket: unable to create UNIX socket %s: %s",
                     addr.sun_path, strerror(errno));
        return 0;
    }
    this->select_max = this->socket + 1;

    /* Set file mode: will not fully work on most system, the group
     * permission is not changed on some Linux and *BSD won't do the
     * chmod. */
    ret = fchmod(this->socket, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
    if (ret == -1) {
        int err = errno;
        SCLogWarning(SC_ERR_INITIALIZATION,
                     "Unable to change permission on socket: %s (%d)",
                     strerror(err),
                     err);
    }
    /* set reuse option */
    ret = setsockopt(this->socket, SOL_SOCKET, SO_REUSEADDR,
                     (char *) &on, sizeof(on));
    if ( ret != 0 ) {
        SCLogWarning(SC_ERR_INITIALIZATION,
                     "Cannot set sockets options: %s.",  strerror(errno));
    }

    /* bind socket */
    ret = bind(this->socket, (struct sockaddr *) &addr, len);
    if (ret == -1) {
        SCLogWarning(SC_ERR_INITIALIZATION,
                     "Unix socket: UNIX socket bind(%s) error: %s",
                     SOCKET_TARGET, strerror(errno));
        return 0;
    }

    /* listen */
    if (listen(this->socket, 1) == -1) {
        SCLogWarning(SC_ERR_INITIALIZATION,
                     "Command server: UNIX socket listen() error: %s",
                     strerror(errno));
        return 0;
    }
    return 1;
}

/**
 * \brief Close the unix socket
 */
void UnixCommandClose(UnixCommand  *this)
{
    if (this->client == -1)
        return;
    SCLogInfo("Unix socket: close client connection");
    close(this->client);
    this->client = -1;
    this->select_max = this->socket + 1;
}

/**
 * \brief Callback function used to send message to socket
 */
int UnixCommandSendCallback(const char *buffer, size_t size, void *data)
{
    UnixCommand *this = (UnixCommand *) data;

    if (send(this->client, buffer, size, 0) == -1) {
        SCLogInfo("Unable to send block: %s", strerror(errno));
        return -1;
    }

    return 0;
}

#define UNIX_PROTO_VERSION_LENGTH 200
#define UNIX_PROTO_VERSION "0.1"

/**
 * \brief Accept a new client on unix socket
 *
 *  The function is called when a new user is detected
 *  in UnixMain(). It does the initial protocol negotiation
 *  with client.
 *
 * \retval 0 in case of error, 1 in case of success
 */
int UnixCommandAccept(UnixCommand *this)
{
    char buffer[UNIX_PROTO_VERSION_LENGTH + 1];
    json_t *client_msg;
    json_t *server_msg;
    json_t *version;
    json_error_t jerror;
    int ret;

    /* accept client socket */
    socklen_t len = sizeof(this->client_addr);
    this->client = accept(this->socket, (struct sockaddr *) &this->client_addr,
                          &len);
    if (this->client < 0) {
        SCLogInfo("Unix socket: accept() error: %s",
                  strerror(errno));
        return 0;
    }
    SCLogDebug("Unix socket: client connection");

    /* read client version */
    buffer[sizeof(buffer)-1] = 0;
    ret = recv(this->client, buffer, sizeof(buffer)-1, 0);
    if (ret < 0) {
        SCLogInfo("Command server: client doesn't send version");
        UnixCommandClose(this);
        return 0;
    }
    if (ret >= (int)(sizeof(buffer)-1)) {
        SCLogInfo("Command server: client message is too long, "
                  "disconnect him.");
        UnixCommandClose(this);
    }
    buffer[ret] = 0;

    client_msg = json_loads(buffer, 0, &jerror);
    if (client_msg == NULL) {
        SCLogInfo("Invalid command, error on line %d: %s\n", jerror.line, jerror.text);
        UnixCommandClose(this);
        return 0;
    }

    version = json_object_get(client_msg, "version");
    if(!json_is_string(version)) {
        SCLogInfo("error: version is not a string");
        UnixCommandClose(this);
        return 0;
    }

    /* check client version */
    if (strcmp(json_string_value(version), UNIX_PROTO_VERSION) != 0) {
        SCLogInfo("Unix socket: invalid client version: \"%s\"",
                json_string_value(version));
        UnixCommandClose(this);
        return 0;
    } else {
        SCLogInfo("Unix socket: client version: \"%s\"",
                json_string_value(version));
    }

    /* send answer */
    server_msg = json_object();
    if (server_msg == NULL) {
        UnixCommandClose(this);
        return 0;
    }
    json_object_set_new(server_msg, "return", json_string("OK"));

    if (json_dump_callback(server_msg, UnixCommandSendCallback, this, 0) == -1) {
        SCLogWarning(SC_ERR_SOCKET, "Unable to send command");
        UnixCommandClose(this);
        return 0;
    }

    /* client connected */
    SCLogInfo("Unix socket: client connected");
    if (this->socket < this->client)
        this->select_max = this->client + 1;
    else
        this->select_max = this->socket + 1;
    return 1;
}

/**
 * \brief Command dispatcher
 *
 * \param this a UnixCommand:: structure
 * \param command a string containing a json formatted
 * command
 *
 * \retval 0 in case of error, 1 in case of success
 */
int UnixCommandExecute(UnixCommand * this, char *command)
{
    int ret = 1;
    json_error_t error;
    json_t *jsoncmd = NULL;
    json_t *cmd = NULL;
    json_t *server_msg = json_object();
    const char * value;

    jsoncmd = json_loads(command, 0, &error);
    if (jsoncmd == NULL) {
        SCLogInfo("Invalid command, error on line %d: %s\n", error.line, error.text);
        return 0;
    }

    if (server_msg == NULL) {
        goto error;
    }

    cmd = json_object_get(jsoncmd, "command");
    if(!json_is_string(cmd)) {
        SCLogInfo("error: command is not a string");
        goto error_cmd;
    }
    value = json_string_value(cmd);

    if (!strcmp(value, "shutdown")) {
        json_object_set_new(server_msg, "message", json_string("Closing Suricata"));
        EngineStop();
    } else {
        json_object_set_new(server_msg, "message", json_string("Unknown command"));
        ret = 0;
    }
    switch (ret) {
        case 0:
            json_object_set_new(server_msg, "return", json_string("NOK"));
            break;
        case 1:
            json_object_set_new(server_msg, "return", json_string("OK"));
            break;
    }

    /* send answer */
    if (json_dump_callback(server_msg, UnixCommandSendCallback, this, 0) == -1) {
        SCLogWarning(SC_ERR_SOCKET, "Unable to send command");
        goto error_cmd;
    }

    json_decref(cmd);
    json_decref(jsoncmd);
    return ret;

error_cmd:
    json_decref(cmd);
error:
    json_decref(jsoncmd);
    UnixCommandClose(this);
    return 0;
}

void UnixCommandRun(UnixCommand * this)
{
    char buffer[4096];
    int ret;
    ret = recv(this->client, buffer, sizeof(buffer) - 1, 0);
    if (ret <= 0) {
        if (ret == 0) {
            SCLogInfo("Unix socket: lost connection with client");
        } else {
            SCLogInfo("Unix socket: error on recv() from client: %s",
                      strerror(errno));
        }
        UnixCommandClose(this);
        return;
    }
    if (ret >= (int)(sizeof(buffer)-1)) {
        SCLogInfo("Command server: client command is too long, "
                  "disconnect him.");
        UnixCommandClose(this);
    }
    buffer[ret] = 0;
    UnixCommandExecute(this, buffer);
}

/**
 * \brief Select function
 *
 * \retval 0 in case of error, 1 in case of success
 */
int UnixMain(UnixCommand * this)
{
    struct timeval tv;
    int ret;

    /* Wait activity on the socket */
    FD_ZERO(&this->select_set);
    FD_SET(this->socket, &this->select_set);
    if (0 <= this->client)
        FD_SET(this->client, &this->select_set);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    ret = select(this->select_max, &this->select_set, NULL, NULL, &tv);

    /* catch select() error */
    if (ret == -1) {
        /* Signal was catched: just ignore it */
        if (errno == EINTR) {
            return 1;
        }
        SCLogInfo("Command server: select() fatal error: %s", strerror(errno));
        return 0;
    }

    /* timeout: continue */
    if (ret == 0) {
        return 1;
    }

    if (0 <= this->client && FD_ISSET(this->client, &this->select_set)) {
        UnixCommandRun(this);
    }
    if (FD_ISSET(this->socket, &this->select_set)) {
        if (!UnixCommandAccept(this))
            return 0;
    }

    return 1;
}

/**
 * \brief Used to kill unix manager thread(s).
 *
 * \todo Kinda hackish since it uses the tv name to identify unix manager
 *       thread.  We need an all weather identification scheme.
 */
void UnixKillUnixManagerThread(void)
{
    ThreadVars *tv = NULL;
    int cnt = 0;

    SCCondSignal(&unix_manager_cond);

    SCMutexLock(&tv_root_lock);

    /* flow manager thread(s) is/are a part of mgmt threads */
    tv = tv_root[TVT_MGMT];

    while (tv != NULL) {
        if (strcasecmp(tv->name, "UnixManagerThread") == 0) {
            TmThreadsSetFlag(tv, THV_KILL);
            TmThreadsSetFlag(tv, THV_DEINIT);

            /* be sure it has shut down */
            while (!TmThreadsCheckFlag(tv, THV_CLOSED)) {
                usleep(100);
            }
            cnt++;
        }
        tv = tv->next;
    }

    /* not possible, unless someone decides to rename UnixManagerThread */
    if (cnt == 0) {
        SCMutexUnlock(&tv_root_lock);
        abort();
    }

    SCMutexUnlock(&tv_root_lock);
    return;
}

void *UnixManagerThread(void *td)
{
    ThreadVars *th_v = (ThreadVars *)td;
    UnixCommand command;

    /* set the thread name */
    (void) SCSetThreadName(th_v->name);
    SCLogDebug("%s started...", th_v->name);

    th_v->sc_perf_pca = SCPerfGetAllCountersArray(&th_v->sc_perf_pctx);
    SCPerfAddToClubbedTMTable(th_v->name, &th_v->sc_perf_pctx);

    if (UnixNew(&command) == 0) {
        int failure_fatal = 0;
        SCLogError(SC_ERR_INITIALIZATION,
                     "Unable to create unix command socket");
        if (ConfGetBool("engine.init-failure-fatal", &failure_fatal) != 1) {
            SCLogDebug("ConfGetBool could not load the value.");
        }
        if (failure_fatal) {
            exit(EXIT_FAILURE);
        } else {
            pthread_exit((void *) 0);
        }
    }

    /* Set the threads capability */
    th_v->cap_flags = 0;
    SCDropCaps(th_v);

    /* Init Unix socket */

    TmThreadsSetFlag(th_v, THV_INIT_DONE);
    while (1) {
        UnixMain(&command);

        if (TmThreadsCheckFlag(th_v, THV_KILL)) {
            UnixCommandClose(&command);
            SCPerfSyncCounters(th_v, 0);
            break;
        }
    }
    TmThreadWaitForFlag(th_v, THV_DEINIT);

    TmThreadsSetFlag(th_v, THV_CLOSED);
    pthread_exit((void *) 0);
}


/** \brief spawn the unix socket manager thread */
void UnixManagerThreadSpawn()
{
    ThreadVars *tv_unixmgr = NULL;

    SCCondInit(&unix_manager_cond, NULL);

    tv_unixmgr = TmThreadCreateMgmtThread("UnixManagerThread",
                                          UnixManagerThread, 0);

    if (tv_unixmgr == NULL) {
        SCLogError(SC_ERR_INITIALIZATION, "TmThreadsCreate failed");
        exit(EXIT_FAILURE);
    }
    if (TmThreadSpawn(tv_unixmgr) != TM_ECODE_OK) {
        SCLogError(SC_ERR_INITIALIZATION, "TmThreadSpawn failed");
        exit(EXIT_FAILURE);
    }

    return;
}

#endif
