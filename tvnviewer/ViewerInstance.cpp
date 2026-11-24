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

#include "ViewerInstance.h"

#include "viewer-core/RemoteViewerCore.h"
#include "viewer-core/FileTransferCapability.h"
#include "AuthenticationDialog.h"
#include "IdentityResource.h"
#include "util/Utf8StringStorage.h"
#include "network/socket/SocketAddressIPv4.h"
#include "client-config-lib/ViewerSettingsManager.h"
#include "thread/AutoLock.h"
#include "thread/LocalMutex.h"

namespace
{
  LocalMutex fingerprintSettingsLock;

  class VerifyServerDialog : public BaseDialog
  {
  public:
    VerifyServerDialog(const StringStorage &endpoint, const StringStorage &fingerprint,
                       const StringStorage *savedFingerprint)
      : BaseDialog(savedFingerprint ? IDD_REPLACE_SERVER_IDENTITY : IDD_VERIFY_SERVER_IDENTITY),
        m_endpoint(endpoint), m_fingerprint(fingerprint), m_savedFingerprint(savedFingerprint) {}

  protected:
    BOOL onInitDialog()
    {
      HWND window = m_ctrlThis.getWindow();
      SetDlgItemText(window, IDC_SERVER_ENDPOINT, m_endpoint.getString());
      SetDlgItemText(window, IDC_SERVER_FINGERPRINT, m_fingerprint.getString());
      if (m_savedFingerprint) {
        UINT8 saved[SecureServerCredentials::FINGERPRINT_SIZE];
        const TCHAR *text = m_savedFingerprint->getString();
        SetDlgItemText(window, IDC_SAVED_SERVER_FINGERPRINT,
                       SecureServerCredentials::parseFingerprint(text, saved)
                         ? text : _T("(Invalid saved fingerprint)"));
      }
      SetFocus(GetDlgItem(window, IDCANCEL));
      return FALSE;
    }

    BOOL onCommand(UINT id, UINT)
    {
      if (id == IDOK || id == IDCANCEL) {
        kill(id);
        return TRUE;
      }
      return FALSE;
    }

  private:
    StringStorage m_endpoint;
    StringStorage m_fingerprint;
    const StringStorage *m_savedFingerprint;
  };

  bool readSavedFingerprint(const StringStorage &setting, StringStorage *saved)
  {
    return !setting.isEmpty() &&
      ViewerSettingsManager::getInstance()->getString(setting.getString(), saved);
  }

  bool matchesFingerprint(const StringStorage &saved, const UINT8 *fingerprint)
  {
    UINT8 expected[SecureServerCredentials::FINGERPRINT_SIZE];
    return SecureServerCredentials::parseFingerprint(saved.getString(), expected) &&
      memcmp(expected, fingerprint, sizeof(expected)) == 0;
  }
}

ViewerInstance::ViewerInstance(WindowsApplication *application,
                               ConnectionData *condata,
                               const ConnectionConfig *conConf)
: m_conConf(*conConf),
  m_condata(*condata),
  m_socket(0),
  m_viewerWnd(application,
              &m_condata,
              &m_conConf,
              ViewerConfig::getInstance()->getLogger()),
  m_vncAuthHandler(&m_condata),
  m_viewerCore(ViewerConfig::getInstance()->getLogger())
{
}

ViewerInstance::ViewerInstance(WindowsApplication *application,
                               ConnectionData *condata,
                               const ConnectionConfig *conConf,
                               SocketIPv4 *socket)
: m_conConf(*conConf),
  m_condata(*condata),
  m_socket(socket),
  m_viewerWnd(application,
              &m_condata,
              &m_conConf,
              ViewerConfig::getInstance()->getLogger()),
  m_vncAuthHandler(&m_condata),
  m_viewerCore(ViewerConfig::getInstance()->getLogger())
{
}


ViewerInstance::~ViewerInstance()
{
  if (m_socket != 0) {
    m_socket->shutdown(SD_BOTH);
    m_socket->close();
  }

  m_viewerCore.stop();
  m_viewerCore.waitTermination();

  if (m_socket != 0) {
    delete m_socket;
    m_socket = NULL;
  }
}

void ViewerInstance::waitViewer()
{
  m_viewerCore.waitTermination();
}

bool ViewerInstance::requiresReconnect() const
{
  return m_viewerWnd.requiresReconnect();
}

bool ViewerInstance::isStopped() const
{
  return m_viewerWnd.isStopped();
}

void ViewerInstance::stop()
{
  m_viewerWnd.postMessage(ViewerWindow::WM_USER_STOP);
}

void ViewerInstance::start()
{
  m_viewerWnd.setRemoteViewerCore(&m_viewerCore);
  m_viewerWnd.setFileTransfer(&m_fileTransfer);

  m_vncAuthHandler.addAuthCapability(&m_viewerCore);

  m_fileTransfer.addCapabilities(&m_viewerCore);

  m_viewerCore.setSecureAuthentication(this);
  if (m_socket) {
    SocketAddressIPv4 peer;
    if (m_socket->getPeerAddr(&peer)) {
      peer.toString(&m_serverEndpoint);
    } else {
      m_serverEndpoint.setString(_T("Incoming connection"));
    }
    m_viewerCore.start(m_socket,
                       &m_viewerWnd, m_conConf.getSharedFlag());
  } else {
    StringStorage strHost;
    m_condata.getReducedHost(&strHost);
    UINT16 portVal = m_condata.getPort();
    m_serverEndpoint.format(_T("%s:%u"), strHost.getString(), static_cast<unsigned>(portVal));
    StringStorage normalizedHost(strHost);
    normalizedHost.toLowerCase();
    m_fingerprintSetting.format(_T("ServerFingerprint.%s.%u"), normalizedHost.getString(),
                                 static_cast<unsigned>(portVal));
    m_viewerCore.start(strHost.getString(), portVal,
                       &m_viewerWnd, m_conConf.getSharedFlag());
  }
}

void ViewerInstance::checkUnencryptedConnection()
{
  AutoLock lock(&fingerprintSettingsLock);
  StringStorage saved;
  if (readSavedFingerprint(m_fingerprintSetting, &saved)) {
    throw IOException(_T("This address has a saved 2LabVnc fingerprint. ")
                      _T("The server no longer offers the expected encrypted connection. ")
                      _T("Verify the server with your administrator."));
  }
}

void ViewerInstance::requestPassword(const UINT8 *fingerprint, std::vector<UINT8> *password)
{
  {
    AutoLock lock(&fingerprintSettingsLock);
    m_hadSavedFingerprint = readSavedFingerprint(m_fingerprintSetting, &m_savedFingerprint);
  }

  if (!m_hadSavedFingerprint || !matchesFingerprint(m_savedFingerprint, fingerprint)) {
    StringStorage text;
    SecureServerCredentials::formatFingerprint(fingerprint, &text);
    VerifyServerDialog confirmation(m_serverEndpoint, text,
                                    m_hadSavedFingerprint ? &m_savedFingerprint : 0);
    if (confirmation.showModal() != IDOK) {
      throw AuthCanceledException();
    }
  }

  AuthenticationDialog dialog(true);
  dialog.setHostName(&m_serverEndpoint);
  if (!dialog.showModal()) {
    throw AuthCanceledException();
  }
  Utf8StringStorage input(dialog.getPassword());
  const size_t length = input.getLength();
  if (length == 0) {
    throw AuthCanceledException(_T("Encryption password cannot be empty"));
  }
  const UINT8 *bytes = reinterpret_cast<const UINT8 *>(input.getString());
  password->assign(bytes, bytes + length);
  SecureZeroMemory(const_cast<UINT8 *>(bytes), length);
}

void ViewerInstance::onAuthenticated(const UINT8 *fingerprint)
{
  if (m_fingerprintSetting.isEmpty()) {
    return; // Reverse connections have no stable server endpoint.
  }
  AutoLock lock(&fingerprintSettingsLock);
  StringStorage current;
  const bool hasCurrent = readSavedFingerprint(m_fingerprintSetting, &current);
  if (hasCurrent && matchesFingerprint(current, fingerprint)) {
    return;
  }
  // Do not replace a pin changed by another connection while the dialog was open.
  if (hasCurrent != m_hadSavedFingerprint ||
      (hasCurrent && !current.isEqualTo(&m_savedFingerprint))) {
    throw IOException(_T("The saved Server fingerprint changed during authentication. Reconnect to verify it."));
  }

  StringStorage text;
  SecureServerCredentials::formatFingerprint(fingerprint, &text);
  if (!ViewerSettingsManager::getInstance()->setString(m_fingerprintSetting.getString(),
                                                       text.getString())) {
    throw IOException(_T("The verified Server fingerprint could not be saved"));
  }
}
