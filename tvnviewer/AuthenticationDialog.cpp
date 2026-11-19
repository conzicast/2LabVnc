// Copyright (C) 2012 GlavSoft LLC.
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

#include "AuthenticationDialog.h"
#include "IdentityResource.h"
#include "network/SecureHandshake.h"

AuthenticationDialog::AuthenticationDialog(bool encryptionMode)
: BaseDialog(IDD_DAUTH), m_encryptionMode(encryptionMode)
{
}


BOOL AuthenticationDialog::onInitDialog() 
{
  setControlById(m_hostname, IDC_EHOST);
  m_hostname.setText(m_strHost.getString());
  setControlById(m_password, IDC_EPASSW);
  setControlById(m_fingerprint, IDC_SERVER_FINGERPRINT);
  if (m_encryptionMode) {
    m_ctrlThis.setText(_T("2LabVnc Password (Full Control or View Only)"));
    m_password.setTextLengthLimit(128);
    m_fingerprint.setTextLengthLimit(64);
    m_fingerprint.setText(m_strFingerprint.getString());
  } else {
    ShowWindow(m_fingerprint.getWindow(), SW_HIDE);
    ShowWindow(GetDlgItem(m_ctrlThis.getWindow(), IDC_FINGERPRINT_HINT), SW_HIDE);
  }
  m_password.setFocus();
  return FALSE;
}

void AuthenticationDialog::setHostName(const StringStorage *hostname)
{
  m_strHost = *hostname;
}

BOOL AuthenticationDialog::onCommand(UINT controlID, UINT notificationID)
{
  if (controlID == IDOK) {
    if (m_encryptionMode) {
      m_fingerprint.getText(&m_strFingerprint);
      UINT8 fingerprint[SecureServerCredentials::FINGERPRINT_SIZE];
      if (!SecureServerCredentials::parseFingerprint(m_strFingerprint.getString(), fingerprint)) {
        MessageBox(m_ctrlThis.getWindow(),
          _T("Enter the 64-character fingerprint from your server administrator."),
          _T("2LabVnc Server Identity"), MB_OK | MB_ICONWARNING);
        m_fingerprint.setFocus();
        return TRUE;
      }
    }
    m_password.getText(&m_strPassword);
    kill(1);
    return TRUE;
  }
  if (controlID == IDCANCEL) {
    kill(0);
    return TRUE;
  }
  return FALSE;
}

const StringStorage *AuthenticationDialog::getPassword()
{
  return &m_strPassword;
}

void AuthenticationDialog::setServerFingerprint(const StringStorage &fingerprint)
{
  m_strFingerprint = fingerprint;
}

const StringStorage &AuthenticationDialog::getServerFingerprint() const
{
  return m_strFingerprint;
}
