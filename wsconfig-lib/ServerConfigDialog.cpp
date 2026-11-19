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

#include "tvnserver/resource.h"
#include "ServerConfigDialog.h"
#include "ConfigDialog.h"
#include "ChangePasswordDialog.h"
#include "server-config-lib/Configurator.h"
#include "util/StringParser.h"
#include "CommonInputValidation.h"
#include "UIDataAccess.h"
#include <limits.h>

ServerConfigDialog::ServerConfigDialog()
: BaseDialog(IDD_CONFIG_SERVER_PAGE), m_parentDialog(NULL),
  m_encryptionCredentialsChanged(false),
  m_encryptionCredentialsPresent(false)
{
}

ServerConfigDialog::~ServerConfigDialog()
{
  SecureZeroMemory(&m_pendingEncryptionCredentials,
                   sizeof(m_pendingEncryptionCredentials));
}

void ServerConfigDialog::setParentDialog(BaseDialog *dialog)
{
  m_parentDialog = dialog;
}

BOOL ServerConfigDialog::onInitDialog()
{
  m_config = Configurator::getInstance()->getServerConfig();
  initControls();
  updateUI();

  return TRUE;
}

BOOL ServerConfigDialog::onNotify(UINT controlID, LPARAM data)
{
  if (controlID == IDC_POLLING_INTERVAL_SPIN) {
    LPNMUPDOWN message = (LPNMUPDOWN)data;
    if (message->hdr.code == UDN_DELTAPOS) {
      onPollingIntervalSpinChangePos(message);
    }
  }
  return TRUE;
}

BOOL ServerConfigDialog::onCommand(UINT controlID, UINT notificationID)
{
  if (notificationID == BN_CLICKED) {
    switch (controlID) {
    case IDC_ACCEPT_RFB_CONNECTIONS:
      onAcceptRfbConnectionsClick();
      break;
    case IDC_ACCEPT_HTTP_CONNECTIONS:
      onAcceptHttpConnectionsClick();
      break;
    case IDC_ENCRYPTION_PASSWORD:
      onEncryptionPasswordChange();
      break;
    case IDC_UNSET_ENCRYPTION_PASSWORD_BUTTON:
      onUnsetEncryptionPasswordClick();
      break;
    case IDC_ENABLE_FILE_TRANSFERS:
      onFileTransferCheckBoxClick();
      break;
    case IDC_REMOVE_WALLPAPER:
      onRemoveWallpaperCheckBoxClick();
      break;
    case IDC_BLOCK_LOCAL_INPUT:
      onBlockLocalInputChanged();
      break;
    case IDC_BLOCK_REMOTE_INPUT:
      onBlockLocalInputChanged();
      break;
    case IDC_LOCAL_INPUT_PRIORITY:
      onLocalInputPriorityChanged();
      break;
    case IDC_USE_D3D:
      onUseD3DChanged();
      break;
    case IDC_USE_MIRROR_DRIVER:
      // FIXME: For high quality code is needed to use a function.
      ((ConfigDialog *)m_parentDialog)->updateApplyButtonState();
      break;
    case IDC_SHOW_TVNCONTROL_ICON_CHECKBOX:
      onShowTrayIconCheckBoxClick();
      break;
    case IDC_SHOW_ENCRYPTION_NOTICE:
      ((ConfigDialog *)m_parentDialog)->updateApplyButtonState();
      break;
    case IDC_CONNECT_RDP_SESSION:
      onConnectToRdpCheckBoxClick();
      break;
    }
  } else if (notificationID == EN_UPDATE) {
    switch (controlID) {
    case IDC_RFB_PORT:
      onRfbPortUpdate();
      break;
    case IDC_HTTP_PORT:
      onHttpPortUpdate();
      break;
    case IDC_POLLING_INTERVAL:
      onPollingIntervalUpdate();
      break;
    case IDC_LOCAL_INPUT_PRIORITY_TIMEOUT:
      onInactivityTimeoutUpdate();
      break;
    }
  }
  return TRUE;
}

bool ServerConfigDialog::validateInput()
{
  bool commonValidationOk =
    CommonInputValidation::validatePort(&m_rfbPort) &&
    CommonInputValidation::validatePort(&m_httpPort) &&
    CommonInputValidation::validateUINT(
      &m_pollingInterval,
      StringTable::getString(IDS_INVALID_POLLING_INTERVAL)) &&
    CommonInputValidation::validateUINT(
      &m_localInputPriorityTimeout,
      StringTable::getString(IDS_INVALID_INACTIVITY_TIMEOUT));

  if (!commonValidationOk) {
    return false;
  }

  int httpPort, rfbPort;

  UIDataAccess::queryValueAsInt(&m_rfbPort, &rfbPort);
  UIDataAccess::queryValueAsInt(&m_httpPort, &httpPort);

  if (rfbPort == httpPort && m_acceptHttpConnections.isChecked()) {
    CommonInputValidation::notifyValidationError(
      &m_httpPort,
      StringTable::getString(IDS_HTTP_RFB_PORTS_ARE_EQUAL));
    return false;
  }

  unsigned int pollingInterval;

  UIDataAccess::queryValueAsUInt(&m_pollingInterval, &pollingInterval);

  if (pollingInterval < ServerConfig::MINIMAL_POLLING_INTERVAL) {
    CommonInputValidation::notifyValidationError(
      &m_pollingInterval,
      StringTable::getString(IDS_POLL_INTERVAL_TOO_SMALL));
    return false;
  }

  unsigned int inactivityTimeout;

  UIDataAccess::queryValueAsUInt(&m_localInputPriorityTimeout, &inactivityTimeout);

  if (inactivityTimeout < ServerConfig::MINIMAL_LOCAL_INPUT_PRIORITY_TIMEOUT) {
    CommonInputValidation::notifyValidationError(
      &m_localInputPriorityTimeout,
      StringTable::getString(IDS_INACTIVITY_TIMEOUT_TOO_SMALL));
    return false;
  }

  if (m_acceptRfbConnections.isChecked() &&
      !m_encryptionCredentialsPresent) {
    MessageBox(m_ctrlThis.getWindow(),
               _T("Set two different connection passwords (at least 16 characters each)."),
               _T("2LabVnc encryption is required"),
               MB_ICONSTOP | MB_OK);
    return false;
  }

  return true;
}

void ServerConfigDialog::updateUI()
{
  m_rfbPort.setSignedInt(m_config->getRfbPort());
  m_httpPort.setSignedInt(m_config->getHttpPort());
  m_pollingInterval.setUnsignedInt(m_config->getPollingInterval());

  m_enableFileTransfers.check(m_config->isFileTransfersEnabled());
  m_removeWallpaper.check(m_config->isRemovingDesktopWallpaperEnabled());

  m_acceptRfbConnections.check(m_config->isAcceptingRfbConnections());
  m_acceptHttpConnections.check(m_config->isAcceptingHttpConnections());

  m_encryptionCredentialsPresent =
    m_config->hasEncryptionCredentials();
  m_encryptionCredentialsChanged = false;
  SecureZeroMemory(&m_pendingEncryptionCredentials,
                   sizeof(m_pendingEncryptionCredentials));
  updateEncryptionPasswordControls();


  m_blockLocalInput.check(m_config->isBlockingLocalInput());
  m_blockRemoteInput.check(m_config->isBlockingRemoteInput());
  m_localInputPriority.check(m_config->isLocalInputPriorityEnabled());
  if (m_config->isLocalInputPriorityEnabled()) {
    m_localInputPriorityTimeout.setEnabled(true);
  }
  m_localInputPriorityTimeout.setUnsignedInt(m_config->getLocalInputPriorityTimeout());

  m_useD3D.check(m_config->getD3DIsAllowed());
  m_useMirrorDriver.check(m_config->getMirrorIsAllowed());

  m_showTrayIcon.check(m_config->getShowTrayIconFlag());
  m_showEncryptionNotice.check(m_config->shouldShowEncryptionNotice());
  m_connectToRdp.check(m_config->getConnectToRdpFlag());

  updateCheckboxesState();
  updateControlDependencies();
}

void ServerConfigDialog::apply()
{
  StringStorage rfbPortText;
  StringStorage httpPortText;
  // Polling interval string storage
  StringStorage pollingIntervalText;

  m_rfbPort.getText(&rfbPortText);
  m_httpPort.getText(&httpPortText);
  m_pollingInterval.getText(&pollingIntervalText);

  int intVal = 0;

  StringParser::parseInt(rfbPortText.getString(), &intVal);
  m_config->setRfbPort(intVal);
  
  StringParser::parseInt(httpPortText.getString(), &intVal);
  m_config->setHttpPort(intVal);

  StringParser::parseInt(pollingIntervalText.getString(), &intVal);
  m_config->setPollingInterval(intVal);

  m_config->enableFileTransfers(m_enableFileTransfers.isChecked());
  m_config->enableRemovingDesktopWallpaper(m_removeWallpaper.isChecked());

  m_config->acceptRfbConnections(m_acceptRfbConnections.isChecked());
  m_config->acceptHttpConnections(m_acceptHttpConnections.isChecked());
  if (m_encryptionCredentialsChanged) {
    if (m_encryptionCredentialsPresent) {
      m_config->setEncryptionCredentials(m_pendingEncryptionCredentials);
    } else {
      m_config->deleteEncryptionCredentials();
    }
    m_encryptionCredentialsChanged = false;
    SecureZeroMemory(&m_pendingEncryptionCredentials,
                     sizeof(m_pendingEncryptionCredentials));
  }

  // Local input priority timeout string storage
  StringStorage liptStringStorage;
  m_localInputPriorityTimeout.getText(&liptStringStorage);
  int timeout = 0;

  m_config->setLocalInputPriority(m_localInputPriority.isChecked());
  if (StringParser::parseInt(liptStringStorage.getString(), &timeout)) {
    timeout = max(0, timeout);
    m_config->setLocalInputPriorityTimeout((unsigned int)timeout);
  }
  m_config->blockLocalInput(m_blockLocalInput.isChecked());
  m_config->blockRemoteInput(m_blockRemoteInput.isChecked());

  m_config->setMirrorAllowing(m_useMirrorDriver.isChecked());
  m_config->setD3DAllowing(m_useD3D.isChecked());
  m_config->setShowTrayIconFlag(m_showTrayIcon.isChecked());
  m_config->setShowEncryptionNotice(m_showEncryptionNotice.isChecked());
  m_config->setConnectToRdpFlag(m_connectToRdp.isChecked());
}

void ServerConfigDialog::initControls()
{
  HWND hwnd = m_ctrlThis.getWindow();
  m_rfbPort.setWindow(GetDlgItem(hwnd, IDC_RFB_PORT));
  m_httpPort.setWindow(GetDlgItem(hwnd, IDC_HTTP_PORT));
  m_pollingInterval.setWindow(GetDlgItem(hwnd, IDC_POLLING_INTERVAL));
  m_useD3D.setWindow(GetDlgItem(hwnd, IDC_USE_D3D));
  m_useMirrorDriver.setWindow(GetDlgItem(hwnd, IDC_USE_MIRROR_DRIVER));
  m_enableFileTransfers.setWindow(GetDlgItem(hwnd, IDC_ENABLE_FILE_TRANSFERS));
  m_removeWallpaper.setWindow(GetDlgItem(hwnd, IDC_REMOVE_WALLPAPER));
  m_acceptRfbConnections.setWindow(GetDlgItem(hwnd, IDC_ACCEPT_RFB_CONNECTIONS));
  m_acceptHttpConnections.setWindow(GetDlgItem(hwnd, IDC_ACCEPT_HTTP_CONNECTIONS));
  m_encryptionPassword.setWindow(GetDlgItem(hwnd, IDC_ENCRYPTION_PASSWORD));
  m_unsetEncryptionPassword.setWindow(
    GetDlgItem(hwnd, IDC_UNSET_ENCRYPTION_PASSWORD_BUTTON));
  m_showTrayIcon.setWindow(GetDlgItem(hwnd, IDC_SHOW_TVNCONTROL_ICON_CHECKBOX));
  m_showEncryptionNotice.setWindow(GetDlgItem(hwnd, IDC_SHOW_ENCRYPTION_NOTICE));
  m_connectToRdp.setWindow(GetDlgItem(hwnd, IDC_CONNECT_RDP_SESSION));

  m_rfbPortSpin.setWindow(GetDlgItem(hwnd, IDC_RFB_PORT_SPIN));
  m_httpPortSpin.setWindow(GetDlgItem(hwnd, IDC_HTTP_PORT_SPIN));
  m_pollingIntervalSpin.setWindow(GetDlgItem(hwnd, IDC_POLLING_INTERVAL_SPIN));

  m_rfbPortSpin.setBuddy(&m_rfbPort);
  m_rfbPortSpin.setAccel(0, 1);
  m_rfbPortSpin.setRange32(1, 65535);

  m_httpPortSpin.setBuddy(&m_httpPort);
  m_httpPortSpin.setAccel(0, 1);
  m_httpPortSpin.setRange32(1, 65535);

  int limitersTmp[] = {50, 200};
  int deltasTmp[] = {5, 10};

  std::vector<int> limitters(limitersTmp, limitersTmp + sizeof(limitersTmp) /
                                                        sizeof(int));
  std::vector<int> deltas(deltasTmp, deltasTmp + sizeof(deltasTmp) /
                                                 sizeof(int));

  m_pollingIntervalSpin.setBuddy(&m_pollingInterval);
  m_pollingIntervalSpin.setAccel(0, 1);
  m_pollingIntervalSpin.setRange32(1, INT_MAX);
  m_pollingIntervalSpin.setAutoAccelerationParams(&limitters, &deltas, 50);
  m_pollingIntervalSpin.enableAutoAcceleration(true);

  m_blockLocalInput.setWindow(GetDlgItem(hwnd, IDC_BLOCK_LOCAL_INPUT));
  m_blockRemoteInput.setWindow(GetDlgItem(hwnd, IDC_BLOCK_REMOTE_INPUT));
  m_localInputPriority.setWindow(GetDlgItem(hwnd, IDC_LOCAL_INPUT_PRIORITY));
  m_localInputPriorityTimeout.setWindow(GetDlgItem(hwnd, IDC_LOCAL_INPUT_PRIORITY_TIMEOUT));
  m_inactivityTimeoutSpin.setWindow(GetDlgItem(hwnd, IDC_INACTIVITY_TIMEOUT_SPIN));

  m_inactivityTimeoutSpin.setBuddy(&m_localInputPriorityTimeout);
  m_inactivityTimeoutSpin.setAccel(0, 1);
  m_inactivityTimeoutSpin.setRange32(0, INT_MAX);

}

//
// TODO: Add comment to this method
//

void ServerConfigDialog::updateControlDependencies()
{
  if (m_acceptRfbConnections.isChecked()) {
    m_rfbPort.setEnabled(true);
    m_acceptHttpConnections.setEnabled(true);
  } else {
    m_rfbPort.setEnabled(false);
    m_acceptHttpConnections.setEnabled(false);
  }

  if ((m_acceptHttpConnections.isChecked()) && (m_acceptHttpConnections.isEnabled())) {
    m_httpPort.setEnabled(true);
  } else {
    m_httpPort.setEnabled(false);
  }

  m_rfbPortSpin.invalidate();
  m_httpPortSpin.invalidate();
  m_pollingIntervalSpin.invalidate();
}

void ServerConfigDialog::onAcceptRfbConnectionsClick()
{
  updateControlDependencies();
  ((ConfigDialog *)m_parentDialog)->updateApplyButtonState();
}

void ServerConfigDialog::onAcceptHttpConnectionsClick()
{
  updateControlDependencies();
  ((ConfigDialog *)m_parentDialog)->updateApplyButtonState();
}

void ServerConfigDialog::onShowTrayIconCheckBoxClick()
{
  bool oldVal = m_config->getShowTrayIconFlag();
  bool newVal = m_showTrayIcon.isChecked();

  if (oldVal != newVal) {
    ((ConfigDialog *)m_parentDialog)->updateApplyButtonState();
  }
}

void ServerConfigDialog::onConnectToRdpCheckBoxClick()
{
  bool oldVal = m_config->getConnectToRdpFlag();
  bool newVal = m_connectToRdp.isChecked();

  if (oldVal != newVal) {
    ((ConfigDialog *)m_parentDialog)->updateApplyButtonState();
  }
}



void ServerConfigDialog::onEncryptionPasswordChange()
{
  SecureServerCredentials credentials;
  try {
    if (!ChangePasswordDialog::promptForConnectionPasswords(&m_ctrlThis, &credentials)) {
      return;
    }
    m_pendingEncryptionCredentials = credentials;
  } catch (const Exception &error) {
    SecureZeroMemory(&credentials, sizeof(credentials));
    MessageBox(m_ctrlThis.getWindow(), error.getMessage(),
               _T("2LabVnc Connection Passwords"), MB_ICONSTOP | MB_OK);
    return;
  }
  SecureZeroMemory(&credentials, sizeof(credentials));
  m_encryptionCredentialsPresent = true;
  m_encryptionCredentialsChanged = true;
  updateEncryptionPasswordControls();
  ((ConfigDialog *)m_parentDialog)->updateApplyButtonState();
}

void ServerConfigDialog::onUnsetEncryptionPasswordClick()
{
  if (MessageBox(m_ctrlThis.getWindow(),
                 _T("Clear both connection passwords? Incoming connections will be disabled until both are set again."),
                 _T("2LabVnc Encryption"),
                 MB_YESNO | MB_ICONQUESTION) != IDYES) {
    return;
  }
  SecureZeroMemory(&m_pendingEncryptionCredentials,
                   sizeof(m_pendingEncryptionCredentials));
  m_encryptionCredentialsPresent = false;
  m_acceptRfbConnections.check(false);
  updateCheckboxesState();
  m_encryptionCredentialsChanged = true;
  updateEncryptionPasswordControls();
  ((ConfigDialog *)m_parentDialog)->updateApplyButtonState();
}

void ServerConfigDialog::updateEncryptionPasswordControls()
{
  m_encryptionPassword.setText(
    m_encryptionCredentialsPresent ? _T("Change...") : _T("Set..."));
  m_unsetEncryptionPassword.setEnabled(m_encryptionCredentialsPresent);
}

void ServerConfigDialog::onPollingIntervalSpinChangePos(LPNMUPDOWN message)
{
  m_pollingIntervalSpin.autoAccelerationHandler(message);
}

void ServerConfigDialog::onRfbPortUpdate()
{
  ((ConfigDialog *)m_parentDialog)->updateApplyButtonState();
}

void ServerConfigDialog::onHttpPortUpdate()
{
  ((ConfigDialog *)m_parentDialog)->updateApplyButtonState();
}

void ServerConfigDialog::onUrlParamsClick()
{
  ((ConfigDialog *)m_parentDialog)->updateApplyButtonState();
}

void ServerConfigDialog::onPollingIntervalUpdate()
{
  ((ConfigDialog *)m_parentDialog)->updateApplyButtonState();
}

void ServerConfigDialog::onFileTransferCheckBoxClick()
{
  ((ConfigDialog *)m_parentDialog)->updateApplyButtonState();
}

void ServerConfigDialog::onRemoveWallpaperCheckBoxClick()
{
  ((ConfigDialog *)m_parentDialog)->updateApplyButtonState();
}

void ServerConfigDialog::onGrabTransparentWindowsChanged()
{
  ((ConfigDialog *)m_parentDialog)->updateApplyButtonState();
}

void ServerConfigDialog::onUseD3DChanged()
{
  ((ConfigDialog *)m_parentDialog)->updateApplyButtonState();
}

void ServerConfigDialog::onBlockLocalInputChanged()
{
  updateCheckboxesState();
  ((ConfigDialog *)m_parentDialog)->updateApplyButtonState();
}

void ServerConfigDialog::onBlockRemoteInputChanged()
{
  updateCheckboxesState();
  ((ConfigDialog *)m_parentDialog)->updateApplyButtonState();
}

void ServerConfigDialog::onLocalInputPriorityChanged()
{
  updateCheckboxesState();
  ((ConfigDialog *)m_parentDialog)->updateApplyButtonState();
}

void ServerConfigDialog::onInactivityTimeoutUpdate()
{
  ((ConfigDialog *)m_parentDialog)->updateApplyButtonState();
}

void ServerConfigDialog::updateCheckboxesState()
{
  if (m_blockLocalInput.isChecked() || m_blockRemoteInput.isChecked()) {
    m_localInputPriority.check(false);
    m_localInputPriority.setEnabled(false);
  } else {
    m_localInputPriority.setEnabled(true);
  }

  if (m_localInputPriority.isChecked() && m_localInputPriority.isEnabled()) {
    m_localInputPriorityTimeout.setEnabled(true);
  } else {
    m_localInputPriorityTimeout.setEnabled(false);
  }
  m_inactivityTimeoutSpin.invalidate();
}
