/* Copyright (C) 2013-2018 Open Information Security Foundation
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
#include "threads.h"
#include "detect-engine.h"
#include "tm-threads.h"
#include "runmodes.h"
#include "conf.h"
#include "runmode-unix-socket.h"

#include "output-json-stats.h"

#include "util-conf.h"
#include "util-privs.h"
#include "util-debug.h"
#include "util-device.h"
#include "util-ebpf.h"
#include "util-signal.h"
#include "util-buffer.h"
#include "util-path.h"
#include "util-profiling.h"

#if (defined BUILD_UNIX_SOCKET) && (defined HAVE_SYS_UN_H) && (defined HAVE_SYS_STAT_H) && (defined HAVE_SYS_TYPES_H)
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "output.h"
#include "output-json.h"

// MSG_NOSIGNAL does not exists on OS X
#ifdef OS_DARWIN
# ifndef MSG_NOSIGNAL
#   define MSG_NOSIGNAL SO_NOSIGPIPE
# endif
#endif

#define SOCKET_PATH LOCAL_STATE_DIR "/run/suricata/"
#define SOCKET_FILENAME "suricata-command.socket"
#define SOCKET_TARGET SOCKET_PATH SOCKET_FILENAME

SCCtrlCondT unix_manager_ctrl_cond;
SCCtrlMutex unix_manager_ctrl_mutex;

#define MAX_FAILED_RULES   20

typedef struct Command_ {
    char *name;
    TmEcode (*Func)(json_t *, json_t *, void *);
    void *data;
    int flags;
    TAILQ_ENTRY(Command_) next;
} Command;

typedef struct Task_ {
    TmEcode (*Func)(void *);
    void *data;
    TAILQ_ENTRY(Task_) next;
} Task;

#define CLIENT_BUFFER_SIZE 4096
typedef struct UnixClient_ {
    int fd;
    MemBuffer *mbuf; /**< buffer for response construction */
    int version;
    TAILQ_ENTRY(UnixClient_) next;
} UnixClient;

typedef struct UnixCommand_ {
    time_t start_timestamp;
    int socket;
    struct sockaddr_un client_addr;
    int select_max;
    TAILQ_HEAD(, Command_) commands;
    TAILQ_HEAD(, Task_) tasks;
    TAILQ_HEAD(, UnixClient_) clients;
} UnixCommand;

/**
 * \brief Create a command unix socket on system
 *
 * \retval 0 in case of error, 1 in case of success
 */
static int UnixNew(UnixCommand * this)
{
    struct sockaddr_un addr;
    int len;
    int ret;
    int on = 1;
    char sockettarget[PATH_MAX];
    const char *socketname;

    this->start_timestamp = time(NULL);
    this->socket = -1;
    this->select_max = 0;

    TAILQ_INIT(&this->commands);
    TAILQ_INIT(&this->tasks);
    TAILQ_INIT(&this->clients);

    int check_dir = 0;
    if (ConfGet("unix-command.filename", &socketname) == 1) {
        if (PathIsAbsolute(socketname)) {
            strlcpy(sockettarget, socketname, sizeof(sockettarget));
        } else {
            snprintf(sockettarget, sizeof(sockettarget), "%s/%s",
                    SOCKET_PATH, socketname);
            check_dir = 1;
        }
    } else {
        strlcpy(sockettarget, SOCKET_TARGET, sizeof(sockettarget));
        check_dir = 1;
    }
    SCLogInfo("Using unix socket file '%s'", sockettarget);

    if (check_dir) {
        struct stat stat_buf;
        /* coverity[toctou] */
        if (stat(SOCKET_PATH, &stat_buf) != 0) {
            /* coverity[toctou] */
            ret = SCMkDir(SOCKET_PATH, S_IRWXU|S_IXGRP|S_IRGRP);
            if (ret != 0) {
                int err = errno;
                if (err != EEXIST) {
                    SCLogError(SC_ERR_INITIALIZATION,
                            "Cannot create socket directory %s: %s",
                            SOCKET_PATH, strerror(err));
                    return 0;
                }
            } else {
                SCLogInfo("Created socket directory %s",
                        SOCKET_PATH);
            }
        }
    }

    /* Remove socket file */
    (void) unlink(sockettarget);

    /* set address */
    addr.sun_family = AF_UNIX;
    strlcpy(addr.sun_path, sockettarget, sizeof(addr.sun_path));
    addr.sun_path[sizeof(addr.sun_path) - 1] = 0;
    len = strlen(addr.sun_path) + sizeof(addr.sun_family) + 1;

    /* create socket */
    this->socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (this->socket == -1) {
        SCLogWarning(SC_ERR_OPENING_FILE,
                     "Unix Socket: unable to create UNIX socket %s: %s",
                     addr.sun_path, strerror(errno));
        return 0;
    }
    this->select_max = this->socket + 1;

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
                     sockettarget, strerror(errno));
        return 0;
    }

#if !(defined OS_FREEBSD || defined __OpenBSD__)
    /* Set file mode: will not fully work on most system, the group
     * permission is not changed on some Linux. *BSD won't do the
     * chmod: it returns EINVAL when calling chmod on sockets. */
    ret = chmod(sockettarget, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
    if (ret == -1) {
        int err = errno;
        SCLogWarning(SC_ERR_INITIALIZATION,
                     "Unable to change permission on socket: %s (%d)",
                     strerror(err),
                     err);
    }
#endif

    /* listen */
    if (listen(this->socket, 1) == -1) {
        SCLogWarning(SC_ERR_INITIALIZATION,
                     "Command server: UNIX socket listen() error: %s",
                     strerror(errno));
        return 0;
    }
    return 1;
}

static void UnixCommandSetMaxFD(UnixCommand *this)
{
    UnixClient *item;

    if (this == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Unix command is NULL, warn devel");
        return;
    }

    this->select_max = this->socket + 1;
    TAILQ_FOREACH(item, &this->clients, next) {
        if (item->fd >= this->select_max) {
            this->select_max = item->fd + 1;
        }
    }
}

static UnixClient *UnixClientAlloc(void)
{
    UnixClient *uclient = SCMalloc(sizeof(UnixClient));
    if (unlikely(uclient == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Can't allocate new client");
        return NULL;
    }
    uclient->mbuf = MemBufferCreateNew(CLIENT_BUFFER_SIZE);
    if (uclient->mbuf == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Can't allocate new client send buffer");
        SCFree(uclient);
        return NULL;
    }
    return uclient;
}

static void UnixClientFree(UnixClient *c)
{
    if (c != NULL) {
        MemBufferFree(c->mbuf);
        SCFree(c);
    }
}

/**
 * \brief Close the unix socket
 */
static void UnixCommandClose(UnixCommand  *this, int fd)
{
    UnixClient *item;
    int found = 0;

    TAILQ_FOREACH(item, &this->clients, next) {
        if (item->fd == fd) {
            found = 1;
            break;
        }
    }

    if (found == 0) {
        SCLogError(SC_ERR_INVALID_VALUE, "No fd found in client list");
        return;
    }

    TAILQ_REMOVE(&this->clients, item, next);

    close(item->fd);
    UnixCommandSetMaxFD(this);
    UnixClientFree(item);
}

#define UNIX_PROTO_VERSION_LENGTH 200
#define UNIX_PROTO_VERSION_V1 "0.1"
#define UNIX_PROTO_V1 1
#define UNIX_PROTO_VERSION "0.2"
#define UNIX_PROTO_V2 2

static int UnixCommandSendJSONToClient(UnixClient *client, json_t *js)
{
    MemBufferReset(client->mbuf);

    OutputJSONMemBufferWrapper wrapper = {
        .buffer = &client->mbuf,
        .expand_by = CLIENT_BUFFER_SIZE
    };

    int r = json_dump_callback(js, OutputJSONMemBufferCallback, &wrapper,
            JSON_PRESERVE_ORDER|JSON_COMPACT|JSON_ENSURE_ASCII|
            JSON_ESCAPE_SLASH);
    if (r != 0) {
        SCLogWarning(SC_ERR_SOCKET, "unable to serialize JSON object");
        return -1;
    }

    if (client->version > UNIX_PROTO_V1) {
        if (MEMBUFFER_OFFSET(client->mbuf) + 1 >= MEMBUFFER_SIZE(client->mbuf)) {
            MemBufferExpand(&client->mbuf, 1);
        }
        MemBufferWriteRaw(client->mbuf, "\n", 1);
    }

    if (send(client->fd, (const char *)MEMBUFFER_BUFFER(client->mbuf),
                MEMBUFFER_OFFSET(client->mbuf), MSG_NOSIGNAL) == -1)
    {
        SCLogWarning(SC_ERR_SOCKET, "unable to send block of size "
                "%"PRIuMAX": %s", (uintmax_t)MEMBUFFER_OFFSET(client->mbuf),
                strerror(errno));
        return -1;
    }

    SCLogDebug("sent message of size %"PRIuMAX" to client socket %d",
            (uintmax_t)MEMBUFFER_OFFSET(client->mbuf), client->fd);
    return 0;
}

/**
 * \brief Accept a new client on unix socket
 *
 *  The function is called when a new user is detected
 *  in UnixMain(). It does the initial protocol negotiation
 *  with client.
 *
 * \retval 0 in case of error, 1 in case of success
 */
static int UnixCommandAccept(UnixCommand *this)
{
    char buffer[UNIX_PROTO_VERSION_LENGTH + 1];
    json_t *client_msg;
    json_t *server_msg;
    json_t *version;
    json_error_t jerror;
    int client;
    int client_version;
    int ret;
    UnixClient *uclient = NULL;

    /* accept client socket */
    socklen_t len = sizeof(this->client_addr);
    client = accept(this->socket, (struct sockaddr *) &this->client_addr,
                          &len);
    if (client < 0) {
        SCLogInfo("Unix socket: accept() error: %s",
                  strerror(errno));
        return 0;
    }
    SCLogDebug("Unix socket: client connection");

    /* read client version */
    buffer[sizeof(buffer)-1] = 0;
    ret = recv(client, buffer, sizeof(buffer)-1, 0);
    if (ret < 0) {
        SCLogInfo("Command server: client doesn't send version");
        close(client);
        return 0;
    }
    if (ret >= (int)(sizeof(buffer)-1)) {
        SCLogInfo("Command server: client message is too long, "
                  "disconnect him.");
        close(client);
        return 0;
    }
    buffer[ret] = 0;

    client_msg = json_loads(buffer, 0, &jerror);
    if (client_msg == NULL) {
        SCLogInfo("Invalid command, error on line %d: %s\n", jerror.line, jerror.text);
        close(client);
        return 0;
    }

    version = json_object_get(client_msg, "version");
    if (!json_is_string(version)) {
        SCLogInfo("error: version is not a string");
        close(client);
        json_decref(client_msg);
        return 0;
    }

    /* check client version */
    if ((strcmp(json_string_value(version), UNIX_PROTO_VERSION) != 0)
        && (strcmp(json_string_value(version), UNIX_PROTO_VERSION_V1) != 0)) {
        SCLogInfo("Unix socket: invalid client version: \"%s\"",
                json_string_value(version));
        json_decref(client_msg);
        close(client);
        return 0;
    } else {
        SCLogDebug("Unix socket: client version: \"%s\"",
                json_string_value(version));
        if (strcmp(json_string_value(version), UNIX_PROTO_VERSION_V1) == 0) {
            client_version = UNIX_PROTO_V1;
        } else {
            client_version = UNIX_PROTO_V2;
        }
    }

    json_decref(client_msg);
    /* send answer */
    server_msg = json_object();
    if (server_msg == NULL) {
        close(client);
        return 0;
    }
    json_object_set_new(server_msg, "return", json_string("OK"));

    uclient = UnixClientAlloc();
    if (unlikely(uclient == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Can't allocate new client");
        json_decref(server_msg);
        close(client);
        return 0;
    }
    uclient->fd = client;
    uclient->version = client_version;

    if (UnixCommandSendJSONToClient(uclient, server_msg) != 0) {
        SCLogWarning(SC_ERR_SOCKET, "Unable to send command");

        UnixClientFree(uclient);
        json_decref(server_msg);
        close(client);
        return 0;
    }

    json_decref(server_msg);

    /* client connected */
    SCLogDebug("Unix socket: client connected");
    TAILQ_INSERT_TAIL(&this->clients, uclient, next);
    UnixCommandSetMaxFD(this);
    return 1;
}

static int UnixCommandBackgroundTasks(UnixCommand* this)
{
    int ret = 1;
    Task *ltask;

    TAILQ_FOREACH(ltask, &this->tasks, next) {
        int fret = ltask->Func(ltask->data);
        if (fret != TM_ECODE_OK) {
            ret = 0;
        }
    }
    return ret;
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
static int UnixCommandExecute(UnixCommand * this, char *command, UnixClient *client)
{
    int ret = 1;
    json_error_t error;
    json_t *jsoncmd = NULL;
    json_t *cmd = NULL;
    json_t *server_msg = json_object();
    const char * value;
    int found = 0;
    Command *lcmd;

    if (server_msg == NULL) {
        return 0;
    }

    jsoncmd = json_loads(command, 0, &error);
    if (jsoncmd == NULL) {
        SCLogInfo("Invalid command, error on line %d: %s\n", error.line, error.text);
        goto error;
    }

    cmd = json_object_get(jsoncmd, "command");
    if(!json_is_string(cmd)) {
        SCLogInfo("error: command is not a string");
        goto error_cmd;
    }
    value = json_string_value(cmd);

    TAILQ_FOREACH(lcmd, &this->commands, next) {
        if (!strcmp(value, lcmd->name)) {
            int fret = TM_ECODE_OK;
            found = 1;
            if (lcmd->flags & UNIX_CMD_TAKE_ARGS) {
                cmd = json_object_get(jsoncmd, "arguments");
                if(!json_is_object(cmd)) {
                    SCLogInfo("error: argument is not an object");
                    goto error_cmd;
                }
            }
            fret = lcmd->Func(cmd, server_msg, lcmd->data);
            if (fret != TM_ECODE_OK) {
                ret = 0;
            }
            break;
        }
    }

    if (found == 0) {
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

    if (UnixCommandSendJSONToClient(client, server_msg) != 0) {
        goto error;
    }

    json_decref(jsoncmd);
    json_decref(server_msg);
    return ret;

error_cmd:
    json_decref(jsoncmd);
error:
    json_decref(server_msg);
    UnixCommandClose(this, client->fd);
    return 0;
}

static void UnixCommandRun(UnixCommand * this, UnixClient *client)
{
    char buffer[4096];
    int ret;
    if (client->version <= UNIX_PROTO_V1) {
        ret = recv(client->fd, buffer, sizeof(buffer) - 1, 0);
        if (ret <= 0) {
            if (ret == 0) {
                SCLogDebug("Unix socket: lost connection with client");
            } else {
                SCLogError(SC_ERR_SOCKET, "Unix socket: error on recv() from client: %s",
                        strerror(errno));
            }
            UnixCommandClose(this, client->fd);
            return;
        }
        if (ret >= (int)(sizeof(buffer)-1)) {
            SCLogError(SC_ERR_SOCKET, "Command server: client command is too long, "
                    "disconnect him.");
            UnixCommandClose(this, client->fd);
        }
        buffer[ret] = 0;
    } else {
        int try = 0;
        int offset = 0;
        int cmd_over = 0;
        ret = recv(client->fd, buffer + offset, sizeof(buffer) - offset - 1, 0);
        do {
            if (ret <= 0) {
                if (ret == 0) {
                    SCLogDebug("Unix socket: lost connection with client");
                } else {
                    SCLogError(SC_ERR_SOCKET, "Unix socket: error on recv() from client: %s",
                            strerror(errno));
                }
                UnixCommandClose(this, client->fd);
                return;
            }
            if (ret >= (int)(sizeof(buffer)- offset - 1)) {
                SCLogInfo("Command server: client command is too long, "
                        "disconnect him.");
                UnixCommandClose(this, client->fd);
            }
            if (buffer[ret - 1] == '\n') {
                buffer[ret-1] = 0;
                cmd_over = 1;
            } else {
                struct timeval tv;
                fd_set select_set;
                offset += ret;
                do {
                    FD_ZERO(&select_set);
                    FD_SET(client->fd, &select_set);
                    tv.tv_sec = 0;
                    tv.tv_usec = 200 * 1000;
                    try++;
                    ret = select(client->fd, &select_set, NULL, NULL, &tv);
                    /* catch select() error */
                    if (ret == -1) {
                        /* Signal was caught: just ignore it */
                        if (errno != EINTR) {
                            SCLogInfo("Unix socket: lost connection with client");
                            UnixCommandClose(this, client->fd);
                            return;
                        }
                    }
                } while (ret == 0 && try < 3);
                if (ret > 0) {
                    ret = recv(client->fd, buffer + offset,
                               sizeof(buffer) - offset - 1, 0);
                }
            }
        } while (try < 3 && cmd_over == 0);

        if (try == 3 && cmd_over == 0) {
            SCLogInfo("Unix socket: imcomplete client message, closing connection");
            UnixCommandClose(this, client->fd);
            return;
        }
    }
    UnixCommandExecute(this, buffer, client);
}

/**
 * \brief Select function
 *
 * \retval 0 in case of error, 1 in case of success
 */
static int UnixMain(UnixCommand * this)
{
    struct timeval tv;
    int ret;
    fd_set select_set;
    UnixClient *uclient;
    UnixClient *tclient;

    /* Wait activity on the socket */
    FD_ZERO(&select_set);
    FD_SET(this->socket, &select_set);
    TAILQ_FOREACH(uclient, &this->clients, next) {
        FD_SET(uclient->fd, &select_set);
    }

    tv.tv_sec = 0;
    tv.tv_usec = 200 * 1000;
    ret = select(this->select_max, &select_set, NULL, NULL, &tv);

    /* catch select() error */
    if (ret == -1) {
        /* Signal was caught: just ignore it */
        if (errno == EINTR) {
            return 1;
        }
        SCLogError(SC_ERR_SOCKET, "Command server: select() fatal error: %s", strerror(errno));
        return 0;
    }

    if (suricata_ctl_flags & SURICATA_STOP) {
        TAILQ_FOREACH_SAFE(uclient, &this->clients, next, tclient) {
            UnixCommandClose(this, uclient->fd);
        }
        return 1;
    }

    /* timeout: continue */
    if (ret == 0) {
        return 1;
    }

    TAILQ_FOREACH_SAFE(uclient, &this->clients, next, tclient) {
        if (FD_ISSET(uclient->fd, &select_set)) {
            UnixCommandRun(this, uclient);
        }
    }
    if (FD_ISSET(this->socket, &select_set)) {
        if (!UnixCommandAccept(this))
            return 1;
    }

    return 1;
}

static TmEcode UnixManagerShutdownCommand(json_t *cmd,
                                   json_t *server_msg, void *data)
{
    SCEnter();
    json_object_set_new(server_msg, "message", json_string("Closing Suricata"));
    EngineStop();
    SCReturnInt(TM_ECODE_OK);
}

static TmEcode UnixManagerVersionCommand(json_t *cmd,
                                   json_t *server_msg, void *data)
{
    SCEnter();
    json_object_set_new(server_msg, "message", json_string(GetProgramVersion()));
    SCReturnInt(TM_ECODE_OK);
}

static TmEcode UnixManagerUptimeCommand(json_t *cmd,
                                 json_t *server_msg, void *data)
{
    SCEnter();
    int uptime;
    UnixCommand *ucmd = (UnixCommand *)data;

    uptime = time(NULL) - ucmd->start_timestamp;
    json_object_set_new(server_msg, "message", json_integer(uptime));
    SCReturnInt(TM_ECODE_OK);
}

static TmEcode UnixManagerRunningModeCommand(json_t *cmd,
                                      json_t *server_msg, void *data)
{
    SCEnter();
    json_object_set_new(server_msg, "message", json_string(RunmodeGetActive()));
    SCReturnInt(TM_ECODE_OK);
}

static TmEcode UnixManagerCaptureModeCommand(json_t *cmd,
                                      json_t *server_msg, void *data)
{
    SCEnter();
    json_object_set_new(server_msg, "message", json_string(RunModeGetMainMode()));
    SCReturnInt(TM_ECODE_OK);
}

static TmEcode UnixManagerReloadRulesWrapper(json_t *cmd, json_t *server_msg, void *data, int do_wait)
{
    SCEnter();

    if (SuriHasSigFile()) {
        json_object_set_new(server_msg, "message",
                            json_string("Live rule reload not possible if -s "
                                        "or -S option used at runtime."));
        SCReturnInt(TM_ECODE_FAILED);
    }

    int r = DetectEngineReloadStart();

    if (r == 0 && do_wait) {
        while (!DetectEngineReloadIsIdle())
            usleep(100);
    } else {
        if (r == -1) {
            json_object_set_new(server_msg, "message", json_string("Reload already in progress"));
            SCReturnInt(TM_ECODE_FAILED);
        }
    }

    json_object_set_new(server_msg, "message", json_string("done"));
    SCReturnInt(TM_ECODE_OK);
}

static TmEcode UnixManagerReloadRules(json_t *cmd, json_t *server_msg, void *data)
{
    return UnixManagerReloadRulesWrapper(cmd, server_msg, data, 1);
}

static TmEcode UnixManagerNonBlockingReloadRules(json_t *cmd, json_t *server_msg, void *data)
{
    return UnixManagerReloadRulesWrapper(cmd, server_msg, data, 0);
}

static TmEcode UnixManagerReloadTimeCommand(json_t *cmd,
                                            json_t *server_msg, void *data)
{
    SCEnter();
    TmEcode retval;
    json_t *jdata = NULL;

    retval = OutputEngineStatsReloadTime(&jdata);
    json_object_set_new(server_msg, "message", jdata);
    SCReturnInt(retval);
}

static TmEcode UnixManagerRulesetStatsCommand(json_t *cmd,
                                              json_t *server_msg, void *data)
{
    SCEnter();
    TmEcode retval;
    json_t *jdata = NULL;

    retval = OutputEngineStatsRuleset(&jdata);
    json_object_set_new(server_msg, "message", jdata);
    SCReturnInt(retval);
}

#ifdef PROFILE_RULES
static TmEcode UnixManagerRulesetProfileCommand(json_t *cmd, json_t *server_msg, void *data)
{
    SCEnter();
    DetectEngineCtx *de_ctx = DetectEngineGetCurrent();

    json_t *js = SCProfileRuleTriggerDump(de_ctx);
    if (js == NULL) {
        json_object_set_new(server_msg, "message", json_string("NOK"));
        SCReturnInt(TM_ECODE_FAILED);
    }
    json_object_set_new(server_msg, "message", js);
    SCReturnInt(TM_ECODE_OK);
}

static TmEcode UnixManagerRulesetProfileStartCommand(json_t *cmd, json_t *server_msg, void *data)
{
    SCEnter();

    int ret = SCProfileRuleStartCollection();
    if (ret != TM_ECODE_OK) {
        json_object_set_new(server_msg, "message", json_string("NOK"));
        SCReturnInt(TM_ECODE_FAILED);
    }
    json_object_set_new(server_msg, "message", json_string("OK"));
    SCReturnInt(TM_ECODE_OK);
}

static TmEcode UnixManagerRulesetProfileStopCommand(json_t *cmd, json_t *server_msg, void *data)
{
    SCEnter();

    int ret = SCProfileRuleStopCollection();
    if (ret != TM_ECODE_OK) {
        json_object_set_new(server_msg, "message", json_string("NOK"));
        SCReturnInt(TM_ECODE_FAILED);
    }
    json_object_set_new(server_msg, "message", json_string("OK"));
    SCReturnInt(TM_ECODE_OK);
}

#endif

static TmEcode UnixManagerShowFailedRules(json_t *cmd,
                                          json_t *server_msg, void *data)
{
    SCEnter();
    int rules_cnt = 0;
    DetectEngineCtx *de_ctx = DetectEngineGetCurrent();
    if (de_ctx == NULL) {
        json_object_set_new(server_msg, "message", json_string("Unable to get info"));
        SCReturnInt(TM_ECODE_OK);
    }

    /* Since we need to deference de_ctx, we don't want to lost it. */
    DetectEngineCtx *list = de_ctx;
    json_t *js_sigs_array = json_array();

    if (js_sigs_array == NULL) {
        json_object_set_new(server_msg, "message", json_string("Unable to get info"));
        goto error;
    }
    while (list) {
        SigString *sigs_str = NULL;
        TAILQ_FOREACH(sigs_str, &list->sig_stat.failed_sigs, next) {
            json_t *jdata = json_object();
            if (jdata == NULL) {
                json_object_set_new(server_msg, "message", json_string("Unable to get the sig"));
                goto error;
            }

            json_object_set_new(jdata, "tenant_id", json_integer(list->tenant_id));
            json_object_set_new(jdata, "rule", json_string(sigs_str->sig_str));
            json_object_set_new(jdata, "filename", json_string(sigs_str->filename));
            json_object_set_new(jdata, "line", json_integer(sigs_str->line));
            if (sigs_str->sig_error) {
                json_object_set_new(jdata, "error", json_string(sigs_str->sig_error));
            }
            json_array_append_new(js_sigs_array, jdata);
            if (++rules_cnt > MAX_FAILED_RULES) {
                break;
            }
        }
        if (rules_cnt > MAX_FAILED_RULES) {
            break;
        }
        list = list->next;
    }

    json_object_set_new(server_msg, "message", js_sigs_array);
    DetectEngineDeReference(&de_ctx);
    SCReturnInt(TM_ECODE_OK);

error:
    DetectEngineDeReference(&de_ctx);
    json_object_clear(js_sigs_array);
    json_decref(js_sigs_array);
    SCReturnInt(TM_ECODE_FAILED);
}

static TmEcode UnixManagerConfGetCommand(json_t *cmd,
                                         json_t *server_msg, void *data)
{
    SCEnter();

    const char *confval = NULL;
    char *variable = NULL;

    json_t *jarg = json_object_get(cmd, "variable");
    if(!json_is_string(jarg)) {
        SCLogInfo("error: variable is not a string");
        json_object_set_new(server_msg, "message", json_string("variable is not a string"));
        SCReturnInt(TM_ECODE_FAILED);
    }

    variable = (char *)json_string_value(jarg);
    if (ConfGet(variable, &confval) != 1) {
        json_object_set_new(server_msg, "message", json_string("Unable to get value"));
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (confval) {
        json_object_set_new(server_msg, "message", json_string(confval));
        SCReturnInt(TM_ECODE_OK);
    }

    json_object_set_new(server_msg, "message", json_string("No string value"));
    SCReturnInt(TM_ECODE_FAILED);
}

static TmEcode UnixManagerListCommand(json_t *cmd,
                               json_t *answer, void *data)
{
    SCEnter();
    json_t *jdata;
    json_t *jarray;
    Command *lcmd = NULL;
    UnixCommand *gcmd = (UnixCommand *) data;
    int i = 0;

    jdata = json_object();
    if (jdata == NULL) {
        json_object_set_new(answer, "message",
                            json_string("internal error at json object creation"));
        return TM_ECODE_FAILED;
    }
    jarray = json_array();
    if (jarray == NULL) {
        json_object_set_new(answer, "message",
                            json_string("internal error at json object creation"));
        return TM_ECODE_FAILED;
    }

    TAILQ_FOREACH(lcmd, &gcmd->commands, next) {
        json_array_append_new(jarray, json_string(lcmd->name));
        i++;
    }

    json_object_set_new(jdata, "count", json_integer(i));
    json_object_set_new(jdata, "commands", jarray);
    json_object_set_new(answer, "message", jdata);
    SCReturnInt(TM_ECODE_OK);
}

static TmEcode UnixManagerReopenLogFiles(json_t *cmd, json_t *server_msg, void *data)
{
    OutputNotifyFileRotation();
    json_object_set_new(server_msg, "message", json_string("done"));
    SCReturnInt(TM_ECODE_OK);
}

#if 0
TmEcode UnixManagerReloadRules(json_t *cmd,
                               json_t *server_msg, void *data)
{
    SCEnter();
    if (suricata_ctl_flags != 0) {
        json_object_set_new(server_msg, "message",
                            json_string("Live rule swap no longer possible."
                                        " Engine in shutdown mode."));
        SCReturn(TM_ECODE_FAILED);
    } else {
        /* FIXME : need to check option value */
        UtilSignalHandlerSetup(SIGUSR2, SignalHandlerSigusr2Idle);
        DetectEngineSpawnLiveRuleSwapMgmtThread();
        json_object_set_new(server_msg, "message", json_string("Reloading rules"));
    }
    SCReturn(TM_ECODE_OK);
}
#endif

static UnixCommand command;

/**
 * \brief Add a command to the list of commands
 *
 * This function adds a command to the list of commands available
 * through the unix socket.
 * 
 * When a command is received from user through the unix socket, the content
 * of 'Command' field in the JSON message is match against keyword, then the
 * Func is called. See UnixSocketAddPcapFile() for an example.
 *
 * \param keyword name of the command
 * \param Func function to run when command is received
 * \param data a pointer to data that are passed to Func when it is run
 * \param flags a flag now used to tune the command type
 * \retval TM_ECODE_OK in case of success, TM_ECODE_FAILED in case of failure
 */
TmEcode UnixManagerRegisterCommand(const char * keyword,
                                   TmEcode (*Func)(json_t *, json_t *, void *),
                                   void *data, int flags)
{
    SCEnter();
    Command *cmd = NULL;
    Command *lcmd = NULL;

    if (Func == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Null function");
        SCReturnInt(TM_ECODE_FAILED);
    }

    if (keyword == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Null keyword");
        SCReturnInt(TM_ECODE_FAILED);
    }

    TAILQ_FOREACH(lcmd, &command.commands, next) {
        if (!strcmp(keyword, lcmd->name)) {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "%s already registered", keyword);
            SCReturnInt(TM_ECODE_FAILED);
        }
    }

    cmd = SCMalloc(sizeof(Command));
    if (unlikely(cmd == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Can't alloc cmd");
        SCReturnInt(TM_ECODE_FAILED);
    }
    cmd->name = SCStrdup(keyword);
    if (unlikely(cmd->name == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Can't alloc cmd name");
        SCFree(cmd);
        SCReturnInt(TM_ECODE_FAILED);
    }
    cmd->Func = Func;
    cmd->data = data;
    cmd->flags = flags;
    /* Add it to the list */
    TAILQ_INSERT_TAIL(&command.commands, cmd, next);

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Add a task to the list of tasks
 *
 * This function adds a task to run in the background. The task is run
 * each time the UnixMain() function exits from select.
 * 
 * \param Func function to run when a command is received
 * \param data a pointer to data that are passed to Func when it is run
 * \retval TM_ECODE_OK in case of success, TM_ECODE_FAILED in case of failure
 */
TmEcode UnixManagerRegisterBackgroundTask(TmEcode (*Func)(void *),
                                          void *data)
{
    SCEnter();
    Task *task = NULL;

    if (Func == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "Null function");
        SCReturnInt(TM_ECODE_FAILED);
    }

    task = SCMalloc(sizeof(Task));
    if (unlikely(task == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Can't alloc task");
        SCReturnInt(TM_ECODE_FAILED);
    }
    task->Func = Func;
    task->data = data;
    /* Add it to the list */
    TAILQ_INSERT_TAIL(&command.tasks, task, next);

    SCReturnInt(TM_ECODE_OK);
}

int UnixManagerInit(void)
{
    if (UnixNew(&command) == 0) {
        int failure_fatal = 0;
        if (ConfGetBool("engine.init-failure-fatal", &failure_fatal) != 1) {
            SCLogDebug("ConfGetBool could not load the value.");
        }
        if (failure_fatal) {
                    FatalError(SC_ERR_FATAL,
                               "Unable to create unix command socket");
        } else {
            SCLogWarning(SC_ERR_INITIALIZATION,
                    "Unable to create unix command socket");
            return -1;
        }
    }

    /* Init Unix socket */
    UnixManagerRegisterCommand("shutdown", UnixManagerShutdownCommand, NULL, 0);
    UnixManagerRegisterCommand("command-list", UnixManagerListCommand, &command, 0);
    UnixManagerRegisterCommand("help", UnixManagerListCommand, &command, 0);
    UnixManagerRegisterCommand("version", UnixManagerVersionCommand, &command, 0);
    UnixManagerRegisterCommand("uptime", UnixManagerUptimeCommand, &command, 0);
    UnixManagerRegisterCommand("running-mode", UnixManagerRunningModeCommand, &command, 0);
    UnixManagerRegisterCommand("capture-mode", UnixManagerCaptureModeCommand, &command, 0);
    UnixManagerRegisterCommand("conf-get", UnixManagerConfGetCommand, &command, UNIX_CMD_TAKE_ARGS);
    UnixManagerRegisterCommand("dump-counters", StatsOutputCounterSocket, NULL, 0);
    UnixManagerRegisterCommand("reload-rules", UnixManagerReloadRules, NULL, 0);
    UnixManagerRegisterCommand("ruleset-reload-rules", UnixManagerReloadRules, NULL, 0);
    UnixManagerRegisterCommand("ruleset-reload-nonblocking", UnixManagerNonBlockingReloadRules, NULL, 0);
    UnixManagerRegisterCommand("ruleset-reload-time", UnixManagerReloadTimeCommand, NULL, 0);
    UnixManagerRegisterCommand("ruleset-stats", UnixManagerRulesetStatsCommand, NULL, 0);
    UnixManagerRegisterCommand("ruleset-failed-rules", UnixManagerShowFailedRules, NULL, 0);
#ifdef PROFILE_RULES
    UnixManagerRegisterCommand("ruleset-profile", UnixManagerRulesetProfileCommand, NULL, 0);
    UnixManagerRegisterCommand(
            "ruleset-profile-start", UnixManagerRulesetProfileStartCommand, NULL, 0);
    UnixManagerRegisterCommand(
            "ruleset-profile-stop", UnixManagerRulesetProfileStopCommand, NULL, 0);
#endif
    UnixManagerRegisterCommand("register-tenant-handler", UnixSocketRegisterTenantHandler, &command, UNIX_CMD_TAKE_ARGS);
    UnixManagerRegisterCommand("unregister-tenant-handler", UnixSocketUnregisterTenantHandler, &command, UNIX_CMD_TAKE_ARGS);
    UnixManagerRegisterCommand("register-tenant", UnixSocketRegisterTenant, &command, UNIX_CMD_TAKE_ARGS);
    UnixManagerRegisterCommand("reload-tenant", UnixSocketReloadTenant, &command, UNIX_CMD_TAKE_ARGS);
    UnixManagerRegisterCommand("unregister-tenant", UnixSocketUnregisterTenant, &command, UNIX_CMD_TAKE_ARGS);
    UnixManagerRegisterCommand("add-hostbit", UnixSocketHostbitAdd, &command, UNIX_CMD_TAKE_ARGS);
    UnixManagerRegisterCommand("remove-hostbit", UnixSocketHostbitRemove, &command, UNIX_CMD_TAKE_ARGS);
    UnixManagerRegisterCommand("list-hostbit", UnixSocketHostbitList, &command, UNIX_CMD_TAKE_ARGS);
    UnixManagerRegisterCommand("reopen-log-files", UnixManagerReopenLogFiles, NULL, 0);
    UnixManagerRegisterCommand("memcap-set", UnixSocketSetMemcap, &command, UNIX_CMD_TAKE_ARGS);
    UnixManagerRegisterCommand("memcap-show", UnixSocketShowMemcap, &command, UNIX_CMD_TAKE_ARGS);
    UnixManagerRegisterCommand("memcap-list", UnixSocketShowAllMemcap, NULL, 0);

    UnixManagerRegisterCommand("dataset-add", UnixSocketDatasetAdd, &command, UNIX_CMD_TAKE_ARGS);
    UnixManagerRegisterCommand("dataset-remove", UnixSocketDatasetRemove, &command, UNIX_CMD_TAKE_ARGS);
    UnixManagerRegisterCommand(
            "get-flow-stats-by-id", UnixSocketGetFlowStatsById, &command, UNIX_CMD_TAKE_ARGS);
    UnixManagerRegisterCommand("dataset-dump", UnixSocketDatasetDump, NULL, 0);
    UnixManagerRegisterCommand(
            "dataset-clear", UnixSocketDatasetClear, &command, UNIX_CMD_TAKE_ARGS);
    UnixManagerRegisterCommand(
            "dataset-lookup", UnixSocketDatasetLookup, &command, UNIX_CMD_TAKE_ARGS);

    return 0;
}

typedef struct UnixManagerThreadData_ {
    int padding;
} UnixManagerThreadData;

static TmEcode UnixManagerThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    UnixManagerThreadData *utd = SCCalloc(1, sizeof(*utd));
    if (utd == NULL)
        return TM_ECODE_FAILED;

    *data = utd;
    return TM_ECODE_OK;
}

static TmEcode UnixManagerThreadDeinit(ThreadVars *t, void *data)
{
    SCFree(data);
    return TM_ECODE_OK;
}

static TmEcode UnixManager(ThreadVars *th_v, void *thread_data)
{
    int ret;

    /* set the thread name */
    SCLogDebug("%s started...", th_v->name);

    StatsSetupPrivate(th_v);

    /* Set the threads capability */
    th_v->cap_flags = 0;
    SCDropCaps(th_v);

    TmThreadsSetFlag(th_v, THV_INIT_DONE | THV_RUNNING);

    while (1) {
        ret = UnixMain(&command);
        if (ret == 0) {
            SCLogError(SC_ERR_FATAL, "Fatal error on unix socket");
        }

        if ((ret == 0) || (TmThreadsCheckFlag(th_v, THV_KILL))) {
            UnixClient *item;
            UnixClient *titem;
            TAILQ_FOREACH_SAFE(item, &(&command)->clients, next, titem) {
                close(item->fd);
                SCFree(item);
            }
            StatsSyncCounters(th_v);
            break;
        }

        UnixCommandBackgroundTasks(&command);
    }
    return TM_ECODE_OK;
}


/** \brief Spawn the unix socket manager thread
 *
 * \param mode if set to 1, init failure cause suricata exit
 * */
void UnixManagerThreadSpawn(int mode)
{
    ThreadVars *tv_unixmgr = NULL;

    SCCtrlCondInit(&unix_manager_ctrl_cond, NULL);
    SCCtrlMutexInit(&unix_manager_ctrl_mutex, NULL);

    tv_unixmgr = TmThreadCreateCmdThreadByName(thread_name_unix_socket,
                                          "UnixManager", 0);

    if (tv_unixmgr == NULL) {
        FatalError(SC_ERR_FATAL, "TmThreadsCreate failed");
    }
    if (TmThreadSpawn(tv_unixmgr) != TM_ECODE_OK) {
        FatalError(SC_ERR_FATAL, "TmThreadSpawn failed");
    }
    if (mode == 1) {
        if (TmThreadsCheckFlag(tv_unixmgr, THV_RUNNING_DONE)) {
            FatalError(SC_ERR_FATAL, "Unix socket init failed");
        }
    }
    return;
}

// TODO can't think of a good name
void UnixManagerThreadSpawnNonRunmode(void)
{
    /* Spawn the unix socket manager thread */
    int unix_socket = ConfUnixSocketIsEnable();
    if (unix_socket == 1) {
        if (UnixManagerInit() == 0) {
            UnixManagerRegisterCommand("iface-stat", LiveDeviceIfaceStat, NULL,
                    UNIX_CMD_TAKE_ARGS);
            UnixManagerRegisterCommand("iface-list", LiveDeviceIfaceList, NULL, 0);
            UnixManagerRegisterCommand("iface-bypassed-stat",
                                       LiveDeviceGetBypassedStats, NULL, 0);
            /* For backward compatibility */
            UnixManagerRegisterCommand("ebpf-bypassed-stat",
                                       LiveDeviceGetBypassedStats, NULL, 0);
            UnixManagerThreadSpawn(0);
        }
    }
}

/**
 * \brief Used to kill unix manager thread(s).
 *
 * \todo Kinda hackish since it uses the tv name to identify unix manager
 *       thread.  We need an all weather identification scheme.
 */
void UnixSocketKillSocketThread(void)
{
    ThreadVars *tv = NULL;

again:
    SCMutexLock(&tv_root_lock);

    /* unix manager thread(s) is/are a part of command threads */
    tv = tv_root[TVT_CMD];

    while (tv != NULL) {
        if (strcasecmp(tv->name, "UnixManagerThread") == 0) {
            /* If the thread dies during init it will have
             * THV_RUNNING_DONE set, so we can set the correct flag
             * and exit.
             */
            if (TmThreadsCheckFlag(tv, THV_RUNNING_DONE)) {
                TmThreadsSetFlag(tv, THV_KILL);
                TmThreadsSetFlag(tv, THV_DEINIT);
                TmThreadsSetFlag(tv, THV_CLOSED);
                break;
            }
            TmThreadsSetFlag(tv, THV_KILL);
            TmThreadsSetFlag(tv, THV_DEINIT);
            /* Be sure it has shut down */
            if (!TmThreadsCheckFlag(tv, THV_CLOSED)) {
                SCMutexUnlock(&tv_root_lock);
                usleep(100);
                goto again;
            }
        }
        tv = tv->next;
    }

    SCMutexUnlock(&tv_root_lock);
    return;
}

#else /* BUILD_UNIX_SOCKET */

void UnixManagerThreadSpawn(int mode)
{
    SCLogError(SC_ERR_UNIMPLEMENTED, "Unix socket is not compiled");
    return;
}

void UnixSocketKillSocketThread(void)
{
    return;
}

void UnixManagerThreadSpawnNonRunmode(void)
{
    return;
}

#endif /* BUILD_UNIX_SOCKET */

void TmModuleUnixManagerRegister (void)
{
#if defined(BUILD_UNIX_SOCKET) && defined(HAVE_SYS_UN_H) && defined(HAVE_SYS_STAT_H) && defined(HAVE_SYS_TYPES_H)
    tmm_modules[TMM_UNIXMANAGER].name = "UnixManager";
    tmm_modules[TMM_UNIXMANAGER].ThreadInit = UnixManagerThreadInit;
    tmm_modules[TMM_UNIXMANAGER].ThreadDeinit = UnixManagerThreadDeinit;
    tmm_modules[TMM_UNIXMANAGER].Management = UnixManager;
    tmm_modules[TMM_UNIXMANAGER].cap_flags = 0;
    tmm_modules[TMM_UNIXMANAGER].flags = TM_FLAG_COMMAND_TM;
#endif /* BUILD_UNIX_SOCKET */
}
