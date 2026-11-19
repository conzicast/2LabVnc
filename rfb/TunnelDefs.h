// Copyright (C) 2013 GlavSoft LLC.
// All rights reserved.
//
//-------------------------------------------------------------------------
// This file is part of the TightVNC software.  Please visit our Web site:
//
//                       http://www.tightvnc.com/
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//-------------------------------------------------------------------------
//

#ifndef __TUNNELDEFS_H__
#define __TUNNELDEFS_H__

#include "util/inttypes.h"

class TunnelDefs
{
public:
  static const UINT32 NOTUNNEL = 0;
  static const UINT32 AESGCM = 0x434E5347;
  // Encrypted ServerInit preference, not a selectable tunnel type.
  static const UINT32 SUPPRESS_ENCRYPTION_NOTICE = 0x434E5348;
  static const char *const SIG_NONE;
  static const char *const VENDOR_AESGCM;
  static const char *const SIG_AESGCM;
  static const char *const SIG_SUPPRESS_ENCRYPTION_NOTICE;
private:
};

#endif // __TUNNELDEFS_H__
