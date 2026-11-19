// End-to-end smoke client for the 2LabVnc server initialization path.
// It verifies mandatory Tight tunneling, performs the production handshake,
// and reads ServerInit over the encrypted channel.

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <algorithm>
#include <iostream>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "network/SecureChannel.h"
#include "network/SecureHandshake.h"
#include "rfb/AuthDefs.h"
#include "rfb/TunnelDefs.h"
#include "util/AnsiStringStorage.h"
#include "util/StringStorage.h"

class SocketChannel : public Channel
{
public:
  SocketChannel(SOCKET socketHandle)
  : m_socket(socketHandle)
  {
  }

  virtual size_t read(void *buffer, size_t length)
  {
    int result = recv(m_socket, static_cast<char *>(buffer),
                      static_cast<int>(std::min<size_t>(length, INT_MAX)), 0);
    if (result == SOCKET_ERROR) {
      throw IOException(_T("RFB smoke client socket read failed"));
    }
    return static_cast<size_t>(result);
  }

  virtual size_t write(const void *buffer, size_t length)
  {
    int result = send(m_socket, static_cast<const char *>(buffer),
                      static_cast<int>(std::min<size_t>(length, INT_MAX)), 0);
    if (result == SOCKET_ERROR) {
      throw IOException(_T("RFB smoke client socket write failed"));
    }
    return static_cast<size_t>(result);
  }

  virtual size_t available()
  {
    u_long count = 0;
    if (ioctlsocket(m_socket, FIONREAD, &count) == SOCKET_ERROR) {
      throw IOException(_T("RFB smoke client availability query failed"));
    }
    return count;
  }

  virtual void close()
  {
    shutdown(m_socket, SD_BOTH);
  }

private:
  SOCKET m_socket;
};

namespace
{
  const UINT16 SMOKE_PORT = 5999;

  void require(bool condition, const TCHAR *message)
  {
    if (!condition) {
      throw IOException(message);
    }
  }

  void readCapability(DataInputStream *input)
  {
    UINT32 code = input->readUInt32();
    char vendor[4];
    char signature[8];
    input->readFully(vendor, sizeof(vendor));
    input->readFully(signature, sizeof(signature));
    require(code == TunnelDefs::AESGCM, _T("Unexpected tunnel capability code"));
    require(memcmp(vendor, TunnelDefs::VENDOR_AESGCM, sizeof(vendor)) == 0,
            _T("Unexpected tunnel vendor signature"));
    require(memcmp(signature, TunnelDefs::SIG_AESGCM,
                   sizeof(signature)) == 0,
            _T("Unexpected tunnel name signature"));
  }
}

int main(int argc, char **argv)
{
  if (argc != 3 || strlen(argv[1]) < 16) {
    std::cerr << "Usage: RfbSmokeClient <test-password> <trusted-fingerprint>" << std::endl;
    return 2;
  }
  StringStorage fingerprintText;
  AnsiStringStorage(argv[2]).toStringStorage(&fingerprintText);
  UINT8 fingerprint[SecureServerCredentials::FINGERPRINT_SIZE];
  if (!SecureServerCredentials::parseFingerprint(fingerprintText.getString(), fingerprint)) {
    std::cerr << "Invalid server fingerprint" << std::endl;
    return 2;
  }

  WSADATA socketData;
  if (WSAStartup(MAKEWORD(2, 2), &socketData) != 0) {
    std::cerr << "WSAStartup failed" << std::endl;
    return 1;
  }

  SOCKET socketHandle = INVALID_SOCKET;
  try {
    socketHandle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    require(socketHandle != INVALID_SOCKET, _T("Socket creation failed"));
    sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(SMOKE_PORT);
    require(connect(socketHandle, reinterpret_cast<sockaddr *>(&address),
                    sizeof(address)) == 0,
            _T("Connection to 2LabVnc smoke server failed"));

    SocketChannel transport(socketHandle);
    SecureChannel secureChannel(&transport);
    DataInputStream input(&secureChannel);
    DataOutputStream output(&secureChannel);

    char serverVersion[12];
    input.readFully(serverVersion, sizeof(serverVersion));
    const char clientVersion[] = "RFB 003.008\n";
    require(memcmp(serverVersion, clientVersion, sizeof(serverVersion)) == 0,
            _T("Unexpected RFB protocol version"));
    output.writeFully(clientVersion, sizeof(serverVersion));
    output.flush();

    UINT8 securityTypeCount = input.readUInt8();
    require(securityTypeCount == 1, _T("Server advertised a downgrade path"));
    require(input.readUInt8() == SecurityDefs::TIGHT,
            _T("Server did not require Tight security"));
    output.writeUInt8(SecurityDefs::TIGHT);
    output.flush();

    require(input.readUInt32() == 1,
            _T("Server did not advertise exactly one secure tunnel"));
    readCapability(&input);
    output.writeUInt32(TunnelDefs::AESGCM);
    output.flush();

    runSecureClientHandshake(
      &input, &output, &secureChannel,
      reinterpret_cast<const UINT8 *>(argv[1]), strlen(argv[1]), fingerprint);
    require(secureChannel.isActive(), _T("Secure channel was not activated"));

    require(input.readUInt32() == 0,
            _T("Smoke server unexpectedly requested legacy VNC authentication"));
    require(input.readUInt32() == 0, _T("Encrypted authentication result failed"));
    output.writeUInt8(1);
    output.flush();

    UINT16 width = input.readUInt16();
    UINT16 height = input.readUInt16();
    require(width > 0 && height > 0, _T("Encrypted ServerInit is invalid"));
    std::vector<UINT8> remainingServerInit(20);
    input.readFully(&remainingServerInit.front(), remainingServerInit.size());

    std::cout << "Encrypted RFB ServerInit received: "
              << width << "x" << height << std::endl;
    closesocket(socketHandle);
    WSACleanup();
    SecureZeroMemory(argv[1], strlen(argv[1]));
    return 0;
  } catch (const Exception &exception) {
    std::wcerr << L"RFB smoke test failed: " << exception.getMessage()
               << std::endl;
    if (socketHandle != INVALID_SOCKET) {
      closesocket(socketHandle);
    }
    WSACleanup();
    SecureZeroMemory(argv[1], strlen(argv[1]));
    return 1;
  }
}
