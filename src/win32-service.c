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
 * \author Ondrej Slanina <oslanina@kerio.com>
 *
 * Windows service functions
 */

#ifdef OS_WIN32

#include "suricata-common.h"
#include "suricata.h"
#include "win32-service.h"
#include "util-debug.h"

/** Append a character, leaving room for the terminating NUL. */
static bool SCServiceAppendChar(char *path, size_t size, size_t *len, char c)
{
    if (size == 0 || *len >= size - 1) {
        return false;
    }
    path[(*len)++] = c;
    path[*len] = '\0';
    return true;
}

/**
 * Quote an argument for the Windows C runtime. Backslashes are literal except
 * before a double quote: emit 2n+1 backslashes before an embedded quote, and
 * 2n before the closing quote. Always quote, including empty arguments.
 */
static bool SCServiceAppendArgument(char *path, size_t size, size_t *len, const char *arg)
{
    if (!SCServiceAppendChar(path, size, len, '"')) {
        return false;
    }
    while (*arg != '\0') {
        size_t backslashes = 0;
        while (*arg == '\\') {
            backslashes++;
            arg++;
        }
        for (size_t i = 0; i < backslashes; i++) {
            if (!SCServiceAppendChar(path, size, len, '\\')) {
                return false;
            }
            if ((*arg == '"' || *arg == '\0') && !SCServiceAppendChar(path, size, len, '\\')) {
                return false;
            }
        }
        if (*arg == '\0') {
            break;
        }
        if (*arg == '"' && !SCServiceAppendChar(path, size, len, '\\')) {
            return false;
        }
        if (!SCServiceAppendChar(path, size, len, *arg++)) {
            return false;
        }
    }
    return SCServiceAppendChar(path, size, len, '"');
}

/** Build the service command line without accessing SCM. */
static bool SCServiceBuildCommandLine(char *path, size_t size, const char *module, int argc,
        const char *const *argv, const char *service_option)
{
    if (size == 0) {
        return false;
    }
    path[0] = '\0';
    size_t len = 0;
    if (!SCServiceAppendArgument(path, size, &len, module)) {
        return false;
    }
    for (int i = 1; i < argc; i++) {
        /* Preserve the existing service-option prefix matching. */
        if (strlen(argv[i]) <= strlen(service_option) &&
                strncmp(service_option, argv[i], strlen(argv[i])) == 0) {
            continue;
        }
        if (!SCServiceAppendChar(path, size, &len, ' ') ||
                !SCServiceAppendArgument(path, size, &len, argv[i])) {
            return false;
        }
    }
    return true;
}

/** Resolve the executable and reject truncation before making any SCM calls. */
static bool SCServiceGetCommandLine(
        char *path, size_t size, int argc, char **argv, const char *service_option)
{
    char module[2048];
    DWORD len = GetModuleFileName(NULL, module, sizeof(module));
    if (len == 0) {
        SCLogError("Can't get path to service binary: %d", (int)GetLastError());
        return false;
    }
    if (len >= sizeof(module)) {
        SCLogError("failed to construct service path string: binary path truncated");
        return false;
    }
    if (!SCServiceBuildCommandLine(
                path, size, module, argc, (const char *const *)argv, service_option)) {
        SCLogError("failed to construct service path string: invalid or truncated command line");
        return false;
    }
    return true;
}

static SERVICE_STATUS_HANDLE service_status_handle = 0;

static int service_argc = 0;

static char **service_argv = NULL;

static int service_initialized = 0;

int main(int argc, char **argv);

/**
 * \brief Detect if running as service or console app
 */
int SCRunningAsService(void)
{
    HANDLE h = INVALID_HANDLE_VALUE;
    if ((h = CreateFile("CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0)) == INVALID_HANDLE_VALUE) {
        SCLogInfo("Running as service: yes");
        return 1;
    }
    CloseHandle(h);
    SCLogInfo("Running as service: no");
    return 0;
}

/**
 * \brief Detect if running as service or console app
 */
static void SCAtExitHandler(void)
{
    SERVICE_STATUS status = {
        SERVICE_WIN32,
        SERVICE_STOPPED,
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
        NO_ERROR,
        NO_ERROR,
        0,
        0
    };

    SCLogInfo("Exit handler called.");

    /* mark service as stopped */
    if (!SetServiceStatus(service_status_handle, &status)) {
        SCLogWarning("Can't set service status: %d", (int)GetLastError());
    } else {
        SCLogInfo("Service status set to: SERVICE_STOPPED");
    }
}

/**
 * \brief Service handler
 */
static DWORD WINAPI SCServiceCtrlHandlerEx(DWORD code, DWORD etype, LPVOID edata, LPVOID context)
{
    if (code == SERVICE_CONTROL_SHUTDOWN || code == SERVICE_CONTROL_STOP) {
        SERVICE_STATUS status = {
            SERVICE_WIN32,
            SERVICE_STOP_PENDING,
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
            NO_ERROR,
            NO_ERROR,
            0,
            0
        };

        SCLogInfo("Service control handler called with %s control code.",
                ((code == SERVICE_CONTROL_SHUTDOWN) ? ("SERVICE_CONTROL_SHUTDOWN") : ("SERVICE_CONTROL_STOP")));

        /* mark service as stop pending */
        if (!SetServiceStatus(service_status_handle, &status)) {
            SCLogWarning("Can't set service status: %d", (int)GetLastError());
        } else {
            SCLogInfo("Service status set to: SERVICE_STOP_PENDING");
        }

        /* mark engine as stopping */
        EngineStop();

        return NO_ERROR;
    }

    return ERROR_CALL_NOT_IMPLEMENTED;
}

/**
 * \brief Service main function
 */
static void WINAPI SCServiceMain(uint32_t argc, char** argv)
{
    SERVICE_STATUS status = {
        SERVICE_WIN32,
        SERVICE_RUNNING,
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
        NO_ERROR,
        NO_ERROR,
        0,
        0
    };

    if ((service_status_handle = RegisterServiceCtrlHandlerEx((char *)PROG_NAME, SCServiceCtrlHandlerEx, NULL)) == (SERVICE_STATUS_HANDLE)0) {
        SCLogError("Can't register service control handler: %d", (int)GetLastError());
        return;
    }

    /* register exit handler */
    if (atexit(SCAtExitHandler)) {
        SCLogWarning("Can't register exit handler: %d", (int)GetLastError());
    }

    /* mark service as running immediately */
    if (!SetServiceStatus(service_status_handle, &status)) {
        SCLogWarning("Can't set service status: %d", (int)GetLastError());
    } else {
        SCLogInfo("Service status set to: SERVICE_RUNNING");
    }

    SCLogInfo("Entering main function...");

    /* suricata initialization -> main loop -> uninitialization */
    main(service_argc, service_argv);

    SCLogInfo("Leaving main function.");

    /* mark service as stopped */
    status.dwCurrentState = SERVICE_STOPPED;

    if (!SetServiceStatus(service_status_handle, &status)) {
        SCLogWarning("Can't set service status: %d", (int)GetLastError());
    } else {
        SCLogInfo("Service status set to: SERVICE_STOPPED");
    }
}

/**
 * \brief Init suricata service
 *
 * \param argc num of arguments
 * \param argv passed arguments
 */
int SCServiceInit(int argc, char **argv)
{
    SERVICE_TABLE_ENTRY	DispatchTable[]	= {
        {(char *)PROG_NAME, (LPSERVICE_MAIN_FUNCTION) SCServiceMain},
        {NULL, NULL}
    };

    /* continue with suricata initialization */
    if (service_initialized) {
        SCLogWarning("Service is already initialized.");
        return 0;
    }

    /* save args */
    service_argc = argc;
    service_argv = argv;

    service_initialized = 1;

    SCLogInfo("Entering service control dispatcher...");

    if (!StartServiceCtrlDispatcher(DispatchTable)) {
        /* exit with failure */
        exit(EXIT_FAILURE);
    }

    SCLogInfo("Leaving service control dispatcher.");

    /* exit with success */
    exit(EXIT_SUCCESS);
}

/**
 * \brief Install suricata as service
 *
 * \param argc num of arguments
 * \param argv passed arguments
 */
int SCServiceInstall(int argc, char **argv)
{
    char path[2048];
    SC_HANDLE service = NULL;
    SC_HANDLE scm = NULL;
    int ret = -1;

    do {
        if (!SCServiceGetCommandLine(path, sizeof(path), argc, argv, "--service-install")) {
            break;
        }

        if ((scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS)) == NULL) {
            SCLogError("Can't open SCM: %d", (int)GetLastError());
            break;
        }

        service = CreateService(
                scm,
                PROG_NAME,
                PROG_NAME,
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                path,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL);

        if (service == NULL) {
            SCLogError("Can't create service: %d", (int)GetLastError());
            break;
        }

        ret = 0;

    } while(0);

    if (service) {
        CloseServiceHandle(service);
    }

    if (scm) {
        CloseServiceHandle(scm);
    }

    return ret;
}

/**
 * \brief Remove suricata service
 *
 * \param argc num of arguments
 * \param argv passed arguments
 */
int SCServiceRemove(void)
{
    SERVICE_STATUS status;
    SC_HANDLE service = NULL;
    SC_HANDLE scm = NULL;
    int ret = -1;

    do {
        if ((scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS)) == NULL) {
            SCLogError("Can't open SCM: %d", (int)GetLastError());
            break;
        }

        if ((service = OpenService(scm, PROG_NAME, SERVICE_ALL_ACCESS)) == NULL) {
            SCLogError("Can't open service: %d", (int)GetLastError());
            break;
        }

        if (!QueryServiceStatus(service, &status)) {
            SCLogError("Can't query service status: %d", (int)GetLastError());
            break;
        }

        if (status.dwCurrentState != SERVICE_STOPPED) {
            SCLogError("Service isn't in stopped state: %d", (int)GetLastError());
            break;
        }

        if (!DeleteService(service)) {
            SCLogError("Can't delete service: %d", (int)GetLastError());
            break;
        }

        ret = 0;

    } while(0);

    if (service) {
        CloseServiceHandle(service);
    }

    if (scm) {
        CloseServiceHandle(scm);
    }

    return ret;
}

/**
 * \brief Change suricata service startup parameters
 *
 * \param argc num of arguments
 * \param argv passed arguments
 */
int SCServiceChangeParams(int argc, char **argv)
{
    char path[2048];
    SC_HANDLE service = NULL;
    SC_HANDLE scm = NULL;
    int ret = -1;

    do {
        if (!SCServiceGetCommandLine(path, sizeof(path), argc, argv, "--service-change-params")) {
            break;
        }

        if ((scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS)) == NULL) {
            SCLogError("Can't open SCM: %d", (int)GetLastError());
            break;
        }

        if ((service = OpenService(scm, PROG_NAME, SERVICE_ALL_ACCESS)) == NULL) {
            SCLogError("Can't open service: %d", (int)GetLastError());
            break;
        }

        if (!ChangeServiceConfig(
                    service,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_DEMAND_START,
                    SERVICE_ERROR_NORMAL,
                    path,
                    NULL,
                    NULL,
                    NULL,
                    NULL,
                    NULL,
                    PROG_NAME))
        {
            SCLogError("Can't change service configuration: %d", (int)GetLastError());
            break;
        }

        ret = 0;

    } while(0);

    return ret;
}

#endif /* OS_WIN32 */
