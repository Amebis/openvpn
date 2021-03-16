/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2019 OpenVPN Inc <sales@openvpn.net>
 *                2021 Simon Rozman <simon@rozman.si>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#elif defined(_MSC_VER)
#include <config-msvc.h>
#endif
#ifdef HAVE_CONFIG_VERSION_H
#include <config-version.h>
#endif

#include "basic.h"
#include "syshead.h"

#include "error.h"
#include "wintun_hlp.h"
#ifdef _WIN32
#include <cfgmgr32.h>
#include <setupapi.h>

typedef struct HSWDEVICE__ *HSWDEVICE;

/**
 * Wintun adapter descriptor.
 */
typedef struct _WINTUN_ADAPTER
{
    HSWDEVICE SwDevice;
    HDEVINFO DevInfo;
    SP_DEVINFO_DATA DevInfoData;
    WCHAR *InterfaceFilename;
    GUID CfgInstanceID;
    WCHAR DevInstanceID[MAX_DEVICE_ID_LEN];
    DWORD LuidIndex;
    DWORD IfType;
    DWORD IfIndex;
} WINTUN_ADAPTER;

static HMODULE wintun = NULL;

WINTUN_CREATE_ADAPTER_FUNC *WintunCreateAdapter;
WINTUN_OPEN_ADAPTER_FUNC *WintunOpenAdapter;
WINTUN_CLOSE_ADAPTER_FUNC *WintunCloseAdapter;
WINTUN_DELETE_DRIVER_FUNC *WintunDeleteDriver;
WINTUN_GET_ADAPTER_LUID_FUNC *WintunGetAdapterLUID;
WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC *WintunGetRunningDriverVersion;
WINTUN_SET_LOGGER_FUNC *WintunSetLogger;
WINTUN_START_SESSION_FUNC *WintunStartSession;
WINTUN_END_SESSION_FUNC *WintunEndSession;
WINTUN_GET_READ_WAIT_EVENT_FUNC *WintunGetReadWaitEvent;
WINTUN_RECEIVE_PACKET_FUNC *WintunReceivePacket;
WINTUN_RELEASE_RECEIVE_PACKET_FUNC *WintunReleaseReceivePacket;
WINTUN_ALLOCATE_SEND_PACKET_FUNC *WintunAllocateSendPacket;
WINTUN_SEND_PACKET_FUNC *WintunSendPacket;

WCHAR WINTUN_TUNNEL_TYPE[MAX_ADAPTER_NAME] = _L(PACKAGE_NAME);

/**
 * Called by internal logger to report diagnostic messages
 *
 * @param Level         Message level.
 *
 * @param Timestamp     Message timestamp in in 100ns intervals since 1601-01-01 UTC.
 *
 * @param Message       Message text.
 */
static void CALLBACK
log_wintun(WINTUN_LOGGER_LEVEL Level, DWORD64 Timestamp, const WCHAR *Message)
{
    unsigned int flags;
    switch (Level)
    {
        case WINTUN_LOG_WARN:
            flags = M_WARN; break;

        case WINTUN_LOG_ERR:
            flags = M_NONFATAL; break;

        default:
            flags = M_DEBUG;
    }
    msg(flags, "Wintun: %ls", Message);
}

DWORD
init_wintun(LPCTSTR path, LPCTSTR instance)
{
    if (wintun != NULL)
    {
        return ERROR_ALREADY_INITIALIZED;
    }

    wintun = LoadLibraryEx(path, NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!wintun)
    {
        DWORD dwResult = GetLastError();
        msg(M_NONFATAL | M_ERRNO, "%s: LoadLibraryExW(\"%ls\") failed", __FUNCTION__, path);
        return dwResult;
    }
#define X(Name) ((*(FARPROC *)&Name = GetProcAddress(wintun, #Name)) == NULL)
    if (
        X(WintunCreateAdapter)
        || X(WintunOpenAdapter)
        || X(WintunCloseAdapter)
        || X(WintunDeleteDriver)
        || X(WintunGetAdapterLUID)
        || X(WintunGetRunningDriverVersion)
        || X(WintunSetLogger)
        || X(WintunStartSession)
        || X(WintunEndSession)
        || X(WintunGetReadWaitEvent)
        || X(WintunReceivePacket)
        || X(WintunReleaseReceivePacket)
        || X(WintunAllocateSendPacket)
        || X(WintunSendPacket))
#undef X
    {
        DWORD dwResult = GetLastError();
        msg(M_NONFATAL | M_ERRNO, "%s: GetProcAddress failed", __FUNCTION__);
        FreeLibrary(wintun);
        return dwResult;
    }
    WintunSetLogger(log_wintun);

    wcscpy_s(WINTUN_TUNNEL_TYPE, _countof(WINTUN_TUNNEL_TYPE), _L(PACKAGE_NAME));
    if (instance)
    {
#ifdef UNICODE
        wcscat_s(WINTUN_TUNNEL_TYPE, _countof(WINTUN_TUNNEL_TYPE), instance);
#else
        const size_t length = wcslen(WINTUN_TUNNEL_TYPE);
        MultiByteToWideChar(CP_UTF8, 0, instance, -1, WINTUN_TUNNEL_TYPE + length, _countof(WINTUN_TUNNEL_TYPE) - length);
#endif
    }

    return ERROR_SUCCESS;
}

bool
is_wintun_initialized(void)
{
    return wintun != NULL;
}

void
get_wintun_adapter_guid(_In_ WINTUN_ADAPTER_HANDLE hAdapter, _Out_ LPGUID pguidAdapter)
{
    memcpy(pguidAdapter, &((const WINTUN_ADAPTER *)hAdapter)->CfgInstanceID, sizeof(GUID));
}

#endif /* ifdef _WIN32 */
