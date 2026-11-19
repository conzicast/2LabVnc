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
#include "util/Utf8StringStorage.h"

namespace
{
  size_t countPasswordCharacters(const TCHAR *password)
  {
    size_t count = 0;
    for (size_t index = 0; password[index] != 0; ++index) {
      ++count;
#ifdef _UNICODE
      if (password[index] >= 0xd800 && password[index] <= 0xdbff &&
          password[index + 1] >= 0xdc00 && password[index + 1] <= 0xdfff) {
        ++index;
      }
#endif
    }
    return count;
  }
}

ChangePasswordDialog::ChangePasswordDialog(Control *parent, bool isNewPassword,
                                           size_t maximumLength,
                                           size_t minimumLength,
                                           bool requireAnsi,
                                           const TCHAR *caption)
: BaseDialog(IDD_CHANGE_PASSWORD), m_allowEmptyPassword(false),
  m_newPassword(isNewPassword), m_maximumLength(maximumLength),
  m_minimumLength(minimumLength), m_requireAnsi(requireAnsi),
  m_passwordsVisible(false), m_passwordMask(0),
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
  SecureZeroMemory(const_cast<TCHAR *>(m_passwordText.getString()),
                   m_passwordText.getLength() * sizeof(TCHAR));
}

bool ChangePasswordDialog::promptForConnectionPasswords(
  Control *parent, SecureServerCredentials *credentials)
{
  const size_t maximum = SecureServerCredentials::MAX_PASSWORD_LENGTH;
  const size_t minimum = SecureServerCredentials::MIN_PASSWORD_LENGTH;
  const HWND owner = parent ? parent->getWindow() : NULL;
  ChangePasswordDialog fullControl(parent, true, maximum, minimum, false,
                                   _T("Set Full-Control Password"));
  if (fullControl.showModal() != IDOK) {
    return false;
  }

  Utf8StringStorage fullPassword(&fullControl.m_passwordText);
  *credentials = SecureServerCredentials::create(
    reinterpret_cast<const UINT8 *>(fullPassword.getString()),
    fullPassword.getLength(), SecureServerCredentials::DEFAULT_ITERATIONS);

  for (;;) {
    ChangePasswordDialog viewOnly(parent, true, maximum, minimum, false,
                                  _T("Set View-Only Password"));
    if (viewOnly.showModal() != IDOK) {
      SecureZeroMemory(credentials, sizeof(*credentials));
      return false;
    }
    Utf8StringStorage viewPassword(&viewOnly.m_passwordText);
    credentials->setViewOnlyPassword(
      reinterpret_cast<const UINT8 *>(viewPassword.getString()),
      viewPassword.getLength());
    if (credentials->hasDistinctPasswords()) {
      return true;
    }
    MessageBox(owner, _T("The full-control and view-only passwords must differ."),
               _T("2LabVnc Connection Passwords"), MB_ICONSTOP | MB_OK);
  }
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
    case IDC_TOGGLE_PASSWORD_VISIBILITY:
      togglePasswordVisibility();
      break;
    }
  }
  return TRUE;
}

void ChangePasswordDialog::togglePasswordVisibility()
{
  m_passwordsVisible = !m_passwordsVisible;
  const WPARAM mask = m_passwordsVisible ? 0 : m_passwordMask;
  const HWND editControls[] = { m_password1.getWindow(), m_password2.getWindow() };
  for (size_t index = 0; index < sizeof(editControls) / sizeof(editControls[0]); ++index) {
    SendMessage(editControls[index], EM_SETPASSWORDCHAR, mask, 0);
    InvalidateRect(editControls[index], NULL, TRUE);
  }
  HWND button = GetDlgItem(m_ctrlThis.getWindow(), IDC_TOGGLE_PASSWORD_VISIBILITY);
  SetWindowText(button, m_passwordsVisible ? _T("Hide passwords") : _T("Show passwords"));
  InvalidateRect(button, NULL, TRUE);
}

BOOL ChangePasswordDialog::onDrawItem(WPARAM controlID, LPDRAWITEMSTRUCT item)
{
  if (controlID != IDC_TOGGLE_PASSWORD_VISIBILITY) {
    return BaseDialog::onDrawItem(controlID, item);
  }

  const int saved = SaveDC(item->hDC);
  if (saved == 0) {
    return FALSE;
  }
  RECT bounds = item->rcItem;
  DrawFrameControl(item->hDC, &bounds, DFC_BUTTON,
    DFCS_BUTTONPUSH | ((item->itemState & ODS_SELECTED) ? DFCS_PUSHED : 0));
  SelectObject(item->hDC, GetStockObject(NULL_BRUSH));
  SelectObject(item->hDC, GetStockObject(DC_PEN));
  SetDCPenColor(item->hDC, GetSysColor(COLOR_BTNTEXT));
  const int x = (bounds.left + bounds.right) / 2;
  const int y = bounds.top + (bounds.bottom - bounds.top) / 3;
  const int radius = (bounds.right - bounds.left) / 5;
  const POINT eye[] = { {x - radius, y}, {x, y - radius / 2},
    {x + radius, y}, {x, y + radius / 2} };
  Polygon(item->hDC, eye, sizeof(eye) / sizeof(eye[0]));
  Ellipse(item->hDC, x - 2, y - 2, x + 3, y + 3);
  if (m_passwordsVisible) {
    MoveToEx(item->hDC, x - radius, y - radius / 2, NULL);
    LineTo(item->hDC, x + radius, y + radius / 2);
  }
  SetBkMode(item->hDC, TRANSPARENT);
  SetTextColor(item->hDC, GetSysColor(COLOR_BTNTEXT));
  RECT label = bounds;
  label.top = y + radius / 2;
  DrawText(item->hDC, m_passwordsVisible ? _T("Hide") : _T("Show"),
           -1, &label, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
  if (item->itemState & ODS_FOCUS) {
    InflateRect(&bounds, -3, -3);
    DrawFocusRect(item->hDC, &bounds);
  }
  RestoreDC(item->hDC, saved);
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

  if (countPasswordCharacters(password1.getString()) < m_minimumLength) {
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
  m_passwordMask = SendMessage(m_password1.getWindow(), EM_GETPASSWORDCHAR, 0, 0);

  m_password1.setTextLengthLimit(m_maximumLength);
  m_password2.setTextLengthLimit(m_maximumLength);
}
