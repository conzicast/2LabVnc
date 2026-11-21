// Copyright (C) 2011,2012 GlavSoft LLC.
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

#include "win-system/Process.h"
#include "win-system/RegistryKey.h"
#include "MsiProperties.h"
#include "util/AnsiStringStorage.h"
#include "util/VncPassCrypt.h"
#include "server-config-lib/Configurator.h"
#include "config-lib/RegistrySettingsManager.h"
#include "tvnserver-app/NamingDefs.h"

#include <msiquery.h>
#include <shlwapi.h>
#include <algorithm>
#include <cstdlib>
//#include <wcautil.h>

const TCHAR SAS_REG_ENTRY[] = _T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
const TCHAR SAS_REG_KEY[] = _T("SoftwareSASGeneration");

void allowSas()
{
  RegistryKey regKey(HKEY_LOCAL_MACHINE,
                     SAS_REG_ENTRY,
                     true);
  int sasValue = 0;
  regKey.getValueAsInt32(SAS_REG_KEY, &sasValue);
  sasValue |= 1;
  regKey.setValueAsInt32(SAS_REG_KEY, sasValue);
}

UINT __stdcall AllowSas(MSIHANDLE hInstall)
{
  allowSas();
  return ERROR_SUCCESS;
}

static void logTrayLaunch(MSIHANDLE install, const TCHAR *message)
{
  const MSIHANDLE record = MsiCreateRecord(0);
  if (record != 0) {
    MsiRecordSetString(record, 0, message);
    MsiProcessMessage(install, INSTALLMESSAGE_INFO, record);
    MsiCloseHandle(record);
  }
}

UINT __stdcall LaunchTrayInInstallerSession(MSIHANDLE install)
{
  try {
    StringStorage data;
    MsiProperties(install).getString(_T("CustomActionData"), &data);
    const TCHAR *value = data.getString();
    TCHAR *separator = 0;
    const DWORD clientPid = _tcstoul(value, &separator, 10);
    DWORD sessionId = 0;
    // Windows Installer runs this action in session 0. Follow the MSI
    // client PID to reach the desktop that launched setup, including RDP.
    if (*value < _T('0') || *value > _T('9') || clientPid == 0 ||
        *separator != _T('|') || separator[1] == 0 ||
        !ProcessIdToSessionId(clientPid, &sessionId) || sessionId == 0) {
      logTrayLaunch(install, _T("2LabVnc tray: no interactive installer session found."));
      return ERROR_INSTALL_FAILURE;
    }

    const DWORD error = Process::startAsSessionUser(
      sessionId, separator + 1, _T("-controlservice -slave"));
    StringStorage message;
    message.format(_T("2LabVnc tray: launch in installer session %lu returned Windows error %lu."),
                   sessionId, error);
    logTrayLaunch(install, message.getString());
    return error == ERROR_SUCCESS ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
  } catch (...) {
    logTrayLaunch(install, _T("2LabVnc tray: could not process installer session data."));
    return ERROR_INSTALL_FAILURE;
  }
}

// FIXME: Code duplication: see the ControlApplication class.
void getCryptedPassword(UINT8 cryptedPass[8], const StringStorage *plainPass)
{
  // Get a copy of the password truncated at 8 characters.
  StringStorage copyOfPlainPass;
  plainPass->getSubstring(&copyOfPlainPass, 0, 7);
  // Convert from TCHAR[] to char[].
  // FIXME: Check exception catching.
  AnsiStringStorage ansiPass(&copyOfPlainPass);

  // Convert to a byte array.
  UINT8 byteArray[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  size_t len = std::min(ansiPass.getLength(), (size_t)8);
  memcpy(byteArray, ansiPass.getString(), len);

  // Encrypt with a fixed key.
  VncPassCrypt::getEncryptedPass(cryptedPass, byteArray);
}

void writePasswordToRegistry(MSIHANDLE hInstall,
                             const TCHAR *registryPath,
                             const TCHAR *entryName)
{
  MsiProperties msiProp(hInstall);
  try {
    StringStorage plainPass;
    msiProp.getString(_T("CustomActionData"), &plainPass);

    UINT8 cryptedPass[8];
    getCryptedPassword(cryptedPass, &plainPass);

    RegistrySecurityAttributes registrySA;
    SECURITY_ATTRIBUTES *sa = 0;
    sa = registrySA.getServiceSA();
    HKEY rootKey = HKEY_LOCAL_MACHINE;
    RegistrySettingsManager sm(rootKey, registryPath, sa);

    if (!sm.setBinaryData(entryName, &cryptedPass[0], 8)) {
      throw Exception(_T("Can't write to the registry."));
    }

  } catch (Exception &e) {
    AnsiStringStorage ansiStr(&StringStorage(e.getMessage()));
    //WcaLog(LOGMSG_STANDARD, ansiStr.getString());
  }
}


UINT __stdcall SetRfbPassword(MSIHANDLE hInstall)
{
  try {
    writePasswordToRegistry(hInstall,
                            RegistryPaths::SERVER_PATH, _T("Password"));
  } catch (...) {
    return ERROR_INSTALL_FAILURE;
  }
  return ERROR_SUCCESS;
}

UINT __stdcall SetViewOnlyPassword(MSIHANDLE hInstall)
{
  try {
    writePasswordToRegistry(hInstall,
                            RegistryPaths::SERVER_PATH, _T("PasswordViewOnly"));
  } catch (...) {
    return ERROR_INSTALL_FAILURE;
  }
  return ERROR_SUCCESS;
}

UINT __stdcall SetControlPassword(MSIHANDLE hInstall)
{
  try {
    writePasswordToRegistry(hInstall,
                            RegistryPaths::SERVER_PATH, _T("ControlPassword"));
  } catch (...) {
    return ERROR_INSTALL_FAILURE;
  }
  return ERROR_SUCCESS;
}

extern "C" BOOL WINAPI DllMain(
                               __in HINSTANCE hInst,
                               __in ULONG ulReason,
                               __in LPVOID
                               )
{
  return TRUE;
}
