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

#ifdef _WIN32
#ifndef OPENVPN_WINTUN_HLP_H
#define OPENVPN_WINTUN_HLP_H

#include <windows.h>
#include <sal.h>
// TODO: Remove once SAL support in MinGW headers is updated.
#ifndef _Out_cap_c_
#define _Out_cap_c_(s)
#endif
#ifndef _Ret_bytecount_
#define _Ret_bytecount_(s)
#endif

#include <wintun.h>

/**
 * wintun.dll function pointers
 */
extern WINTUN_CREATE_ADAPTER_FUNC WintunCreateAdapter;
extern WINTUN_DELETE_ADAPTER_FUNC WintunDeleteAdapter;
extern WINTUN_DELETE_POOL_DRIVER_FUNC WintunDeletePoolDriver;
extern WINTUN_ENUM_ADAPTERS_FUNC WintunEnumAdapters;
extern WINTUN_FREE_ADAPTER_FUNC WintunFreeAdapter;
extern WINTUN_OPEN_ADAPTER_FUNC WintunOpenAdapter;
extern WINTUN_GET_ADAPTER_LUID_FUNC WintunGetAdapterLUID;
extern WINTUN_GET_ADAPTER_NAME_FUNC WintunGetAdapterName;
extern WINTUN_SET_ADAPTER_NAME_FUNC WintunSetAdapterName;
extern WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC WintunGetRunningDriverVersion;
extern WINTUN_SET_LOGGER_FUNC WintunSetLogger;
extern WINTUN_START_SESSION_FUNC WintunStartSession;
extern WINTUN_END_SESSION_FUNC WintunEndSession;
extern WINTUN_GET_READ_WAIT_EVENT_FUNC WintunGetReadWaitEvent;
extern WINTUN_RECEIVE_PACKET_FUNC WintunReceivePacket;
extern WINTUN_RELEASE_RECEIVE_PACKET_FUNC WintunReleaseReceivePacket;
extern WINTUN_ALLOCATE_SEND_PACKET_FUNC WintunAllocateSendPacket;
extern WINTUN_SEND_PACKET_FUNC WintunSendPacket;

/**
 * Pool name we are using to declare ownership of Wintun adapters
 */
extern const WCHAR WINTUN_POOL[];

/**
 * Loads wintun.dll and gets its entry points.
 *
 * @return ERROR_SUCCESS on success; Win32 error code otherwise
 */
DWORD
init_wintun(void);

/**
 * Checks if wintun.dll is loaded.
 *
 * @return true if wintun.dll is loaded; false otherwise.
 */
bool
is_wintun_initialized(void);

/**
 * Returns network adapter ID.
 *
 * @param hAdapter      Adapter handle obtained with WintunOpenAdapter or WintunCreateAdapter.
 *
 * @param pguidAdapter  A pointer to GUID that receives network adapter ID.
 */
void
get_wintun_adapter_guid(_In_ WINTUN_ADAPTER_HANDLE hAdapter, _Out_ LPGUID pguidAdapter);

#endif /* ifndef OPENVPN_WINTUN_HLP_H */
#endif /* ifdef _WIN32 */
