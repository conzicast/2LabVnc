// Copyright (C) 2010,2011,2012 GlavSoft LLC.
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

#include "SecurityAttributes.h"
#include <memory>

SecurityAttributes::SecurityAttributes()
: m_isDefaultAttributes(true)
{
  ZeroMemory(&m_securityAttributes, sizeof(SECURITY_ATTRIBUTES));
  m_securityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
}

SecurityAttributes::~SecurityAttributes()
{
}

void SecurityAttributes::setDefaultAttributes()
{
  m_isDefaultAttributes = true;
}

void SecurityAttributes::shareToAllUsers()
{
  SecurityIdentifier localUsers(_T("S-1-1-0"));

  EXPLICIT_ACCESS explisitAccess;
  ZeroMemory(&explisitAccess, sizeof(EXPLICIT_ACCESS));

  // All access for local users.
  explisitAccess.grfAccessPermissions = GENERIC_ALL;
  explisitAccess.grfAccessMode = SET_ACCESS;
  explisitAccess.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
  explisitAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
  explisitAccess.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
  explisitAccess.Trustee.ptstrName  = (LPTSTR)localUsers.getSid();

  try {
    m_sd.setRulesAsDacl(1, &explisitAccess);
  } catch (...) {
    m_isDefaultAttributes = true;
  }

  m_securityAttributes.lpSecurityDescriptor = m_sd.getSD();

  m_isDefaultAttributes = false;
}

void SecurityAttributes::configureControlPipe()
{
  SecurityIdentifier everyone(_T("S-1-1-0"));
  SecurityIdentifier administrators(_T("S-1-5-32-544"));
  SecurityIdentifier system(_T("S-1-5-18"));
  std::auto_ptr<SecurityIdentifier> owner(SecurityIdentifier::getProcessOwner(GetCurrentProcess()));
  SID *principals[] = { everyone.getSid(), administrators.getSid(),
                         system.getSid(), owner->getSid() };
  EXPLICIT_ACCESS rules[4] = {};
  for (size_t index = 0; index < sizeof(rules) / sizeof(rules[0]); ++index) {
    // FILE_APPEND_DATA aliases FILE_CREATE_PIPE_INSTANCE. Status clients
    // get explicit I/O rights, without the right to create a server instance.
    rules[index].grfAccessPermissions = index == 0 ?
      (FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES) : FILE_ALL_ACCESS;
    rules[index].grfAccessMode = SET_ACCESS;
    rules[index].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    rules[index].Trustee.ptstrName = reinterpret_cast<LPTSTR>(principals[index]);
  }
  m_sd.setRulesAsDacl(sizeof(rules) / sizeof(rules[0]), rules);
  m_securityAttributes.lpSecurityDescriptor = m_sd.getSD();
  m_isDefaultAttributes = false;
}

SECURITY_ATTRIBUTES *SecurityAttributes::getSecurityAttributes()
{
  if (m_isDefaultAttributes) {
    return 0;
  } else {
    return &m_securityAttributes;
  }
}

void SecurityAttributes::setInheritable()
{
  m_isDefaultAttributes = false;
  m_securityAttributes.bInheritHandle = TRUE;
}
