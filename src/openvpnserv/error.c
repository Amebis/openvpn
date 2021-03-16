/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2021 Simon Rozman <simon@rozman.si>
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

#include "service.h"

#include <stdbool.h>
#include <stdarg.h>

unsigned int x_debug_level; /* GLOBAL */

bool
dont_mute(unsigned int flags)
{
    UNREFERENCED_PARAMETER(flags);

    return true;
}

void
x_msg_va(const unsigned int flags, const char *format, va_list arglist)
{
    char line[256];
    openvpn_vsnprintf(line, sizeof(line), format, arglist);
    MsgToEventLog(flags, TEXT("%hs"), line);
}

void
x_msg(const unsigned int flags, const char *format, ...)
{
    va_list arglist;
    va_start(arglist, format);
    x_msg_va(flags, format, arglist);
    va_end(arglist);
}
