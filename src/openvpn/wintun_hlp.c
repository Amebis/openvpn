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

/**
 * Declarations taken from https://git.zx2c4.com/wintun/tree/api/adapter.h
 */
#define MAX_INSTANCE_ID MAX_PATH

/**
 * Wintun adapter descriptor.
 */
typedef struct _WINTUN_ADAPTER
{
    GUID CfgInstanceID;
    WCHAR DevInstanceID[MAX_INSTANCE_ID];
    DWORD LuidIndex;
    DWORD IfType;
    WCHAR Pool[WINTUN_MAX_POOL];
} WINTUN_ADAPTER;

static HMODULE wintun = NULL;

WINTUN_CREATE_ADAPTER_FUNC WintunCreateAdapter;
WINTUN_DELETE_ADAPTER_FUNC WintunDeleteAdapter;
WINTUN_DELETE_POOL_DRIVER_FUNC WintunDeletePoolDriver;
WINTUN_ENUM_ADAPTERS_FUNC WintunEnumAdapters;
WINTUN_FREE_ADAPTER_FUNC WintunFreeAdapter;
WINTUN_OPEN_ADAPTER_FUNC WintunOpenAdapter;
WINTUN_GET_ADAPTER_LUID_FUNC WintunGetAdapterLUID;
WINTUN_GET_ADAPTER_NAME_FUNC WintunGetAdapterName;
WINTUN_SET_ADAPTER_NAME_FUNC WintunSetAdapterName;
WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC WintunGetRunningDriverVersion;
WINTUN_SET_LOGGER_FUNC WintunSetLogger;
WINTUN_START_SESSION_FUNC WintunStartSession;
WINTUN_END_SESSION_FUNC WintunEndSession;
WINTUN_GET_READ_WAIT_EVENT_FUNC WintunGetReadWaitEvent;
WINTUN_RECEIVE_PACKET_FUNC WintunReceivePacket;
WINTUN_RELEASE_RECEIVE_PACKET_FUNC WintunReleaseReceivePacket;
WINTUN_ALLOCATE_SEND_PACKET_FUNC WintunAllocateSendPacket;
WINTUN_SEND_PACKET_FUNC WintunSendPacket;

WCHAR WINTUN_POOL[WINTUN_MAX_POOL] = _L(PACKAGE_NAME);

/**
 * Called by internal logger to report diagnostic messages
 *
 * @param Level         Message level.
 *
 * @param Message       Message text.
 */
static void CALLBACK
log_wintun(WINTUN_LOGGER_LEVEL Level, const WCHAR *Message)
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
#define X(Name, Type) ((Name = (Type)GetProcAddress(wintun, #Name)) == NULL)
    if (X(WintunCreateAdapter, WINTUN_CREATE_ADAPTER_FUNC)
        || X(WintunDeleteAdapter, WINTUN_DELETE_ADAPTER_FUNC)
        || X(WintunDeletePoolDriver, WINTUN_DELETE_POOL_DRIVER_FUNC)
        || X(WintunEnumAdapters, WINTUN_ENUM_ADAPTERS_FUNC)
        || X(WintunFreeAdapter, WINTUN_FREE_ADAPTER_FUNC)
        || X(WintunOpenAdapter, WINTUN_OPEN_ADAPTER_FUNC)
        || X(WintunGetAdapterLUID, WINTUN_GET_ADAPTER_LUID_FUNC)
        || X(WintunGetAdapterName, WINTUN_GET_ADAPTER_NAME_FUNC)
        || X(WintunSetAdapterName, WINTUN_SET_ADAPTER_NAME_FUNC)
        || X(WintunGetRunningDriverVersion, WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC)
        || X(WintunSetLogger, WINTUN_SET_LOGGER_FUNC)
        || X(WintunStartSession, WINTUN_START_SESSION_FUNC)
        || X(WintunEndSession, WINTUN_END_SESSION_FUNC)
        || X(WintunGetReadWaitEvent, WINTUN_GET_READ_WAIT_EVENT_FUNC)
        || X(WintunReceivePacket, WINTUN_RECEIVE_PACKET_FUNC)
        || X(WintunReleaseReceivePacket, WINTUN_RELEASE_RECEIVE_PACKET_FUNC)
        || X(WintunAllocateSendPacket, WINTUN_ALLOCATE_SEND_PACKET_FUNC)
        || X(WintunSendPacket, WINTUN_SEND_PACKET_FUNC))
#undef X
    {
        DWORD dwResult = GetLastError();
        msg(M_NONFATAL | M_ERRNO, "%s: GetProcAddress failed", __FUNCTION__);
        FreeLibrary(wintun);
        return dwResult;
    }
    WintunSetLogger(log_wintun);

    wcscpy_s(WINTUN_POOL, _countof(WINTUN_POOL), _L(PACKAGE_NAME));
    if (instance)
    {
#ifdef UNICODE
        wcscat_s(WINTUN_POOL, _countof(WINTUN_POOL), instance);
#else
        const size_t length = wcslen(WINTUN_POOL);
        MultiByteToWideChar(CP_UTF8, 0, instance, -1, WINTUN_POOL + length, _countof(WINTUN_POOL) - length);
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
