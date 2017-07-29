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
        SCLogWarning(SC_ERR_SVC, "Can't set service status: %d", (int)GetLastError());
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
            SCLogWarning(SC_ERR_SVC, "Can't set service status: %d", (int)GetLastError());
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
        SCLogError(SC_ERR_SVC, "Can't register service control handler: %d", (int)GetLastError());
        return;
    }

    /* register exit handler */
    if (atexit(SCAtExitHandler)) {
        SCLogWarning(SC_ERR_SVC, "Can't register exit handler: %d", (int)GetLastError());
    }

    /* mark service as running immediately */
    if (!SetServiceStatus(service_status_handle, &status)) {
        SCLogWarning(SC_ERR_SVC, "Can't set service status: %d", (int)GetLastError());
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
        SCLogWarning(SC_ERR_SVC, "Can't set service status: %d", (int)GetLastError());
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
        {PROG_NAME, (LPSERVICE_MAIN_FUNCTION) SCServiceMain},
        {NULL, NULL}
    };

    /* continue with suricata initialization */
    if (service_initialized) {
        SCLogWarning(SC_ERR_SVC, "Service is already initialized.");
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
    int i = 0;

    do {
        memset(path, 0, sizeof(path));

        if (GetModuleFileName(NULL, path, MAX_PATH) == 0 ){
            SCLogError(SC_ERR_SVC, "Can't get path to service binary: %d", (int)GetLastError());
            break;
        }

        /* skip name of binary itself */
        for (i = 1; i < argc; i++) {
            if ((strlen(argv[i]) <= strlen("--service-install")) && (strncmp("--service-install", argv[i], strlen(argv[i])) == 0)) {
                continue;
            }
            strlcat(path, " ", sizeof(path) - strlen(path) - 1);
            strlcat(path, argv[i], sizeof(path) - strlen(path) - 1);
        }

        if ((scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS)) == NULL) {
            SCLogError(SC_ERR_SVC, "Can't open SCM: %d", (int)GetLastError());
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
            SCLogError(SC_ERR_SVC, "Can't create service: %d", (int)GetLastError());
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
int SCServiceRemove(int argc, char **argv)
{
    SERVICE_STATUS status;
    SC_HANDLE service = NULL;
    SC_HANDLE scm = NULL;
    int ret = -1;

    do {
        if ((scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS)) == NULL) {
            SCLogError(SC_ERR_SVC, "Can't open SCM: %d", (int)GetLastError());
            break;
        }

        if ((service = OpenService(scm, PROG_NAME, SERVICE_ALL_ACCESS)) == NULL) {
            SCLogError(SC_ERR_SVC, "Can't open service: %d", (int)GetLastError());
            break;
        }

        if (!QueryServiceStatus(service, &status)) {
            SCLogError(SC_ERR_SVC, "Can't query service status: %d", (int)GetLastError());
            break;
        }

        if (status.dwCurrentState != SERVICE_STOPPED) {
            SCLogError(SC_ERR_SVC, "Service isn't in stopped state: %d", (int)GetLastError());
            break;
        }

        if (!DeleteService(service)) {
            SCLogError(SC_ERR_SVC, "Can't delete service: %d", (int)GetLastError());
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
    int i = 0;

    do {
        memset(path, 0, sizeof(path));

        if (GetModuleFileName(NULL, path, MAX_PATH) == 0 ){
            SCLogError(SC_ERR_SVC, "Can't get path to service binary: %d", (int)GetLastError());
            break;
        }

        /* skip name of binary itself */
        for (i = 1; i < argc; i++) {
            if ((strlen(argv[i]) <= strlen("--service-change-params")) && (strncmp("--service-change-params", argv[i], strlen(argv[i])) == 0)) {
                continue;
            }
            strlcat(path, " ", sizeof(path) - strlen(path) - 1);
            strlcat(path, argv[i], sizeof(path) - strlen(path) - 1);
        }

        if ((scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS)) == NULL) {
            SCLogError(SC_ERR_SVC, "Can't open SCM: %d", (int)GetLastError());
            break;
        }

        if ((service = OpenService(scm, PROG_NAME, SERVICE_ALL_ACCESS)) == NULL) {
            SCLogError(SC_ERR_SVC, "Can't open service: %d", (int)GetLastError());
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
            SCLogError(SC_ERR_SVC, "Can't change service configuration: %d", (int)GetLastError());
            break;
        }

        ret = 0;

    } while(0);

    return ret;
}

#endif /* OS_WIN32 */
