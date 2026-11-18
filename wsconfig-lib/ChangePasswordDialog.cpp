// Copyright (C) 2009,2010,2011,2012 GlavSoft LLC.
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

#include "ChangePasswordDialog.h"
#include "tvnserver/resource.h"

#include "server-config-lib/ServerConfig.h"

#include "util/VncPassCrypt.h"
#include "util/AnsiStringStorage.h"

ChangePasswordDialog::ChangePasswordDialog(Control *parent, bool isNewPassword,
                                           size_t maximumLength,
                                           size_t minimumLength,
                                           bool requireAnsi,
                                           const TCHAR *caption)
: BaseDialog(IDD_CHANGE_PASSWORD), m_allowEmptyPassword(false),
  m_newPassword(isNewPassword), m_maximumLength(maximumLength),
  m_minimumLength(minimumLength), m_requireAnsi(requireAnsi),
  m_caption(caption == 0 ? _T("") : caption)
{
  setParent(parent);

  m_passwordEmptyTooltip.setText(StringTable::getString(IDS_PASSWORD_IS_EMPTY));
  m_passwordEmptyTooltip.setTitle(StringTable::getString(IDS_MBC_TVNCONTROL));

  m_passwordsNotMatchTooltip.setText(StringTable::getString(IDS_PASSWORDS_NOT_MATCH));
  m_passwordsNotMatchTooltip.setTitle(StringTable::getString(IDS_MBC_TVNCONTROL));

  StringStorage minimumLengthMessage;
  minimumLengthMessage.format(
    _T("Password must contain at least %u characters."),
    static_cast<unsigned int>(m_minimumLength));
  m_passwordWeakTooltip.setText(minimumLengthMessage.getString());
  m_passwordWeakTooltip.setTitle(StringTable::getString(IDS_MBC_BAD_PASSWORD));

  m_passwordEncodingTooltip.setText(StringTable::getString(IDS_BAD_PASSWORD));
  m_passwordEncodingTooltip.setTitle(StringTable::getString(IDS_MBC_BAD_PASSWORD));
}

ChangePasswordDialog::~ChangePasswordDialog()
{
}

const TCHAR *ChangePasswordDialog::getPasswordInPlainText() const
{
  return m_passwordText.getString();
}

BOOL ChangePasswordDialog::onInitDialog()
{
  initControls();
  if (!m_caption.isEmpty()) {
    m_ctrlThis.setText(m_caption.getString());
  } else if (m_newPassword) {
    m_ctrlThis.setText(StringTable::getString(IDS_NEW_PASSWORD));
  } else {
    m_ctrlThis.setText(StringTable::getString(IDS_CHANGE_PASSWORD));
  }
  return TRUE;
}

BOOL ChangePasswordDialog::onCommand(UINT cID, UINT nID)
{
  if (nID == BN_CLICKED) {
    switch (cID) {
    case IDOK:
      onOkButtonClick();
      break;
    case IDCANCEL:
      onCancelButtonClick();
      break;
    }
  }
  return TRUE;
}

void ChangePasswordDialog::onOkButtonClick()
{
  StringStorage password1;
  StringStorage password2;
  m_password1.getText(&password1);
  m_password2.getText(&password2);

  if (password1.isEmpty() && !m_allowEmptyPassword) {
    m_password1.showBalloonTip(&m_passwordEmptyTooltip);
    m_password1.setFocus();
    return ;
  }
  if (!password1.isEqualTo(&password2)) {
    m_password2.showBalloonTip(&m_passwordsNotMatchTooltip);
    m_password2.setFocus();
    return ;
  }

  if (password1.getLength() < m_minimumLength) {
    m_password1.showBalloonTip(&m_passwordWeakTooltip);
    m_password1.setFocus();
    return;
  }

  if (m_requireAnsi && !AnsiStringStorage::checkAnsiConversion(password1)) {
    m_password1.showBalloonTip(&m_passwordEncodingTooltip);
    m_password1.setFocus();
    return;
  }

  m_passwordText.setString(password1.getString());

  kill(IDOK);
}

void ChangePasswordDialog::onCancelButtonClick()
{
  kill(IDCANCEL);
}

void ChangePasswordDialog::initControls()
{
  HWND hwnd = m_ctrlThis.getWindow();
  m_password1.setWindow(GetDlgItem(hwnd, IDC_PASSWORD));
  m_password2.setWindow(GetDlgItem(hwnd, IDC_PASSWORD2));

  m_password1.setTextLengthLimit(m_maximumLength);
  m_password2.setTextLengthLimit(m_maximumLength);
}
