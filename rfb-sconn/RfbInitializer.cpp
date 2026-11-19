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

#define _CRT_RAND_S  // BEFORE <stdlib.h>
#include <stdlib.h>

#include "RfbInitializer.h"
#include "thread/AutoLock.h"
#include "rfb/VendorDefs.h"
#include "rfb/AuthDefs.h"
#include "CapContainer.h"
#include "server-config-lib/Configurator.h"
#include "AuthException.h"
#include "win-system/Environment.h"
#include "util/AnsiStringStorage.h"
#include "tvnserver-app/NamingDefs.h"
#include "network/SecureHandshake.h"
#include "network/socket/SocketStream.h"
#include "rfb/TunnelDefs.h"

namespace
{
  const DWORD HANDSHAKE_DEADLINE_MS = 15000;
}

RfbInitializer::RfbInitializer(SecureChannel *stream,
                               ClientAuthListener *extAuthListener,
                               RfbClient *client, SocketStream *transport)
: m_shared(false),
  m_tightEnabled(false),
  m_minorVerNum(0),
  m_extAuthListener(extAuthListener),
  m_client(client),
  m_secureChannel(stream),
  m_transport(transport),
  m_viewOnlyAuth(false)
{
  m_output = new DataOutputStream(stream);
  m_input = new DataInputStream(stream);
}

RfbInitializer::~RfbInitializer()
{
  delete m_output;
  delete m_input;
}

void RfbInitializer::authPhase()
{
  m_transport->setDeadline(HANDSHAKE_DEADLINE_MS);
  initVersion();
  initAuthenticate();
  readClientInit();
}

void RfbInitializer::afterAuthPhase(const CapContainer *srvToClCaps,
                                    const CapContainer *clToSrvCaps,
                                    const CapContainer *encCaps,
                                    const Dimension *dim,
                                    const PixelFormat *pf)
{
  sendServerInit(dim, pf);
  sendDesktopName();
  if (m_tightEnabled) {
    sendInteractionCaps(srvToClCaps, clToSrvCaps, encCaps);
  }
}

void RfbInitializer::initVersion()
{
  char initVersionMsg[] = "RFB 003.008\n";
  char clientVersionMsg[13];
  size_t msgLen = 12;
  m_output->writeFully(initVersionMsg, msgLen);
  m_input->readFully(clientVersionMsg, msgLen);
  clientVersionMsg[12] = 0;
  m_minorVerNum = getProtocolMinorVersion(clientVersionMsg);

  try {
    checkForLoopback();
    // Checking for a ban before auth and then after.
    checkForBan();
  } catch (Exception &e) {
    if (m_minorVerNum == 3) {
      m_output->writeUInt32(0);
    } else {
      m_output->writeUInt8(0);
    }
    AnsiStringStorage reason(&StringStorage(e.getMessage()));
    unsigned int reasonLen = (unsigned int)reason.getLength();
    _ASSERT(reasonLen == reason.getLength());

    m_output->writeUInt32(reasonLen);
    m_output->writeFully(reason.getString(), reasonLen);

    throw;
  }
}

void RfbInitializer::checkForLoopback()
{
  SocketAddressIPv4 sockAddr;
  m_client->getSocketAddr(&sockAddr);
  struct sockaddr_in addrIn = sockAddr.getSockAddr();

  bool isLoopback = (unsigned long)addrIn.sin_addr.S_un.S_addr == 16777343;

  ServerConfig *srvConf = Configurator::getInstance()->getServerConfig();
  if (isLoopback && !srvConf->isLoopbackConnectionsAllowed()) {
    throw Exception(_T("Sorry, loopback connections are not enabled"));
  }
  if (srvConf->isOnlyLoopbackConnectionsAllowed() && !isLoopback) {
    throw Exception(_T("Your connection has been rejected"));
  }
}

void RfbInitializer::doTightAuth()
{
  ServerConfig *serverConfig =
    Configurator::getInstance()->getServerConfig();
  if (!serverConfig->hasEncryptionCredentials()) {
    throw AuthException(_T("Configure both 2LabVnc connection passwords on the server"));
  }

  CapContainer tunnelInfo;
  tunnelInfo.addCap(TunnelDefs::AESGCM,
                    TunnelDefs::VENDOR_AESGCM,
                    TunnelDefs::SIG_AESGCM);
  m_output->writeUInt32(tunnelInfo.getCapCount());
  tunnelInfo.sendCaps(m_output);
  m_output->flush();

  UINT32 selectedTunnel = m_input->readUInt32();
  if (selectedTunnel != TunnelDefs::AESGCM) {
    throw AuthException(_T("The viewer did not select required AES-256-GCM encryption"));
  }

  SecureServerCredentials credentials;
  serverConfig->getEncryptionCredentials(&credentials);
  try {
    m_viewOnlyAuth =
      runSecureServerHandshake(m_input, m_output, m_secureChannel, credentials);
  } catch (const SecurePasswordException &) {
    SecureZeroMemory(&credentials, sizeof(credentials));
    m_extAuthListener->onAuthFailed(m_client);
    throw;
  } catch (...) {
    SecureZeroMemory(&credentials, sizeof(credentials));
    throw;
  }
  SecureZeroMemory(&credentials, sizeof(credentials));

  // The tunnel already authenticated the client and assigned its role.
  m_output->writeUInt32(0);
  // The local approval prompt has its own configured timeout.
  m_transport->clearDeadline(0);
  m_extAuthListener->onCheckAccessControl(m_client);
  m_transport->setDeadline(HANDSHAKE_DEADLINE_MS);
  if (m_minorVerNum >= 8) {
    m_output->writeUInt32(0); // Successful RFB security result.
  }
}

void RfbInitializer::initAuthenticate()
{
  try {
    // Determine effective security type from the configuration.
    // Here the protocol varies between versions 3.3 and 3.7+.
    if (m_minorVerNum >= 7) {
      // Encryption is mandatory, so the legacy unencrypted security type is
      // deliberately not advertised as a downgrade path.
      m_output->writeUInt8(1);
      m_output->writeUInt8(SecurityDefs::TIGHT);
      // Read what the client has actually selected.
      UINT8 clientSecType = m_input->readUInt8();
      if (clientSecType == SecurityDefs::TIGHT) {
        m_tightEnabled = true;
        doTightAuth();
      } else {
        throw AuthException(_T("This server requires 2LabVnc encrypted mode"));
      }
    } else {
      throw AuthException(_T("RFB 3.7 or later is required for encryption"));
    }
  } catch (AuthException &e) {
    // FIXME: The authentication result must be sent in protocols 3.3 and 3.7
    //        as well, unless the authentication was set to AuthDefs::NONE.
    if (m_minorVerNum >= 8) {
      AnsiStringStorage reason(&StringStorage(e.getMessage()));
      unsigned int reasonLen = (unsigned int)reason.getLength();
      _ASSERT(reasonLen == reason.getLength());

      m_output->writeUInt32(1); // FIXME: Use a named constant instead of 1.
      m_output->writeUInt32(reasonLen);
      m_output->writeFully(reason.getString(), reasonLen);
    }
    throw;
  }
}

void RfbInitializer::readClientInit()
{
  m_shared = m_input->readUInt8() != 0;
}

void RfbInitializer::sendServerInit(const Dimension *dim,
                                    const PixelFormat *pf)
{
  m_output->writeUInt16((UINT16)dim->width);
  m_output->writeUInt16((UINT16)dim->height);
  // Pixel format
  m_output->writeUInt8((UINT8)pf->bitsPerPixel);
  m_output->writeUInt8((UINT8)pf->colorDepth);
  m_output->writeUInt8((UINT8)pf->bigEndian);
  m_output->writeUInt8(1);
  m_output->writeUInt16((UINT16)pf->redMax);
  m_output->writeUInt16((UINT16)pf->greenMax);
  m_output->writeUInt16((UINT16)pf->blueMax);
  m_output->writeUInt8((UINT8)pf->redShift);
  m_output->writeUInt8((UINT8)pf->greenShift);
  m_output->writeUInt8((UINT8)pf->blueShift);
  // Padding
  m_output->writeUInt8(0);
  m_output->writeUInt16(0);
}

void RfbInitializer::sendDesktopName()
{
  StringStorage deskName;
  if (!Environment::getComputerName(&deskName)) {
    deskName.setString(DefaultNames::DEFAULT_COMPUTER_NAME);
  }

  AnsiStringStorage ansiName(&deskName);
  unsigned int dnLen = (unsigned int)ansiName.getLength();
  _ASSERT(dnLen == ansiName.getLength());

  m_output->writeUInt32(dnLen);
  m_output->writeFully(ansiName.getString(), dnLen);
}

void RfbInitializer::sendInteractionCaps(const CapContainer *srvToClCaps,
                                         const CapContainer *clToSrvCaps,
                                         const CapContainer *encCaps)
{
  m_output->writeUInt16(srvToClCaps->getCapCount());
  m_output->writeUInt16(clToSrvCaps->getCapCount());
  m_output->writeUInt16(encCaps->getCapCount());
  m_output->writeUInt16(0); // Pad

  srvToClCaps->sendCaps(m_output);
  clToSrvCaps->sendCaps(m_output);
  encCaps->sendCaps(m_output);
}

unsigned int RfbInitializer::getProtocolMinorVersion(const char str[12])
{
  if ( str[0] != 'R' || str[1] != 'F' || str[2] != 'B' || str[3] != ' ' ||
       !isdigit(str[4]) || !isdigit(str[5]) || !isdigit(str[6]) ||
       str[7] != '.' ||
       !isdigit(str[8]) || !isdigit(str[9]) || !isdigit(str[10]) ||
       str[11] != '\n' ) {
    throw Exception(_T("Invalid format of the RFB version message"));
  }

  unsigned int majorVersion =
    (str[4] - '0') * 100 + (str[5] - '0') * 10 + (str[6] - '0');
  if (majorVersion != 3) {
    throw Exception(_T("Unsupported RFB protocol version requested"));
  }

  unsigned int minorVersion =
    (str[8] - '0') * 100 + (str[9] - '0') * 10 + (str[10] - '0');
  return minorVersion;
}

void RfbInitializer::checkForBan()
{
  if (m_extAuthListener->onCheckForBan(m_client)) {
    throw AuthException(_T("Your connection has been rejected"));
  }
}
