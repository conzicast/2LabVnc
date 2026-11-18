// Focused tests for the encrypted channel record layer.

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <algorithm>
#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

#include <winsock2.h>
#include <ws2tcpip.h>

#include "network/SecureChannel.h"
#include "network/SecureHandshake.h"

class MemoryChannel : public Channel
{
public:
  MemoryChannel(size_t maximumRead, size_t maximumWrite)
  : m_position(0),
    m_maximumRead(maximumRead),
    m_maximumWrite(maximumWrite),
    m_closed(false)
  {
  }

  virtual size_t read(void *buffer, size_t length)
  {
    if (m_position == m_bytes.size()) {
      return 0;
    }
    size_t availableBytes = m_bytes.size() - m_position;
    size_t bytesToRead = std::min(length, availableBytes);
    bytesToRead = std::min(bytesToRead, m_maximumRead);
    memcpy(buffer, &m_bytes[m_position], bytesToRead);
    m_position += bytesToRead;
    return bytesToRead;
  }

  virtual size_t write(const void *buffer, size_t length)
  {
    size_t bytesToWrite = std::min(length, m_maximumWrite);
    const UINT8 *source = static_cast<const UINT8 *>(buffer);
    m_bytes.insert(m_bytes.end(), source, source + bytesToWrite);
    return bytesToWrite;
  }

  virtual size_t available()
  {
    return m_bytes.size() - m_position;
  }

  virtual void close()
  {
    m_closed = true;
  }

  void rewind()
  {
    m_position = 0;
  }

  std::vector<UINT8> &bytes()
  {
    return m_bytes;
  }

private:
  std::vector<UINT8> m_bytes;
  size_t m_position;
  size_t m_maximumRead;
  size_t m_maximumWrite;
  bool m_closed;
};

class SocketTestChannel : public Channel
{
public:
  SocketTestChannel(SOCKET socketHandle)
  : m_socket(socketHandle)
  {
  }

  virtual size_t read(void *buffer, size_t length)
  {
    int result = recv(m_socket, static_cast<char *>(buffer),
                      static_cast<int>(std::min<size_t>(length, INT_MAX)), 0);
    if (result == SOCKET_ERROR) {
      throw IOException(_T("Socket test read failed"));
    }
    return static_cast<size_t>(result);
  }

  virtual size_t write(const void *buffer, size_t length)
  {
    int result = send(m_socket, static_cast<const char *>(buffer),
                      static_cast<int>(std::min<size_t>(length, INT_MAX)), 0);
    if (result == SOCKET_ERROR) {
      throw IOException(_T("Socket test write failed"));
    }
    return static_cast<size_t>(result);
  }

  virtual size_t available()
  {
    u_long bytesAvailable = 0;
    if (ioctlsocket(m_socket, FIONREAD, &bytesAvailable) == SOCKET_ERROR) {
      throw IOException(_T("Socket test availability query failed"));
    }
    return bytesAvailable;
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
  const UINT8 TEST_KEY[SecureChannel::KEY_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
  };
  const UINT8 TEST_NONCE_PREFIX[SecureChannel::NONCE_PREFIX_SIZE] = {
    0xA0, 0xA1, 0xA2, 0xA3
  };

  void require(bool condition, const char *message)
  {
    if (!condition) {
      std::cerr << "FAILED: " << message << std::endl;
      exit(1);
    }
  }

  std::vector<UINT8> makePayload(size_t size)
  {
    std::vector<UINT8> payload(size);
    for (size_t index = 0; index < payload.size(); ++index) {
      payload[index] = static_cast<UINT8>((index * 31 + 17) & 0xFF);
    }
    return payload;
  }

  void testPassThrough()
  {
    MemoryChannel memory(5, 7);
    SecureChannel channel(&memory);
    const char message[] = "plain RFB negotiation";

    size_t written = channel.write(message, sizeof(message));
    require(written == 7, "pass-through must preserve partial writes");
    require(!channel.isActive(), "channel must start in pass-through mode");
  }

  void testEncryptedRoundTrip()
  {
    MemoryChannel memory(7, 11);
    SecureChannel channel(&memory);
    channel.activate(TEST_KEY, TEST_KEY,
                     TEST_NONCE_PREFIX, TEST_NONCE_PREFIX);

    std::vector<UINT8> expected = makePayload(150000);
    require(channel.write(&expected.front(), expected.size()) == expected.size(),
            "encrypted write must consume the full plaintext");

    memory.rewind();
    std::vector<UINT8> actual(expected.size());
    size_t totalRead = 0;
    while (totalRead < actual.size()) {
      totalRead += channel.read(&actual[totalRead], actual.size() - totalRead);
    }
    require(actual == expected,
            "multiple fragmented encrypted records must round-trip");
  }

  void testTamperDetection()
  {
    MemoryChannel memory(13, 17);
    SecureChannel channel(&memory);
    channel.activate(TEST_KEY, TEST_KEY,
                     TEST_NONCE_PREFIX, TEST_NONCE_PREFIX);

    std::vector<UINT8> payload = makePayload(4096);
    channel.write(&payload.front(), payload.size());
    require(memory.bytes().size() > 32, "encrypted record is unexpectedly short");
    memory.bytes()[20] ^= 0x40;
    memory.rewind();

    bool rejected = false;
    try {
      std::vector<UINT8> output(payload.size());
      channel.read(&output.front(), output.size());
    } catch (const IOException &) {
      rejected = true;
    }
    require(rejected, "modified ciphertext must be rejected");
  }

  void testSequenceDetection()
  {
    MemoryChannel memory(19, 23);
    SecureChannel channel(&memory);
    channel.activate(TEST_KEY, TEST_KEY,
                     TEST_NONCE_PREFIX, TEST_NONCE_PREFIX);

    std::vector<UINT8> payload = makePayload(128);
    channel.write(&payload.front(), payload.size());
    memory.bytes()[15] = 1;
    memory.rewind();

    bool rejected = false;
    try {
      std::vector<UINT8> output(payload.size());
      channel.read(&output.front(), output.size());
    } catch (const IOException &) {
      rejected = true;
    }
    require(rejected, "out-of-sequence records must be rejected");
  }

  void runHandshake(const char *serverPassword,
                    const char *clientPassword,
                    SecureSessionKeys *serverKeys,
                    SecureSessionKeys *clientKeys)
  {
    SecureServerCredentials credentials = SecureServerCredentials::create(
      reinterpret_cast<const UINT8 *>(serverPassword),
      strlen(serverPassword),
      100000);
    SecureServerHandshake server(credentials);
    SecureClientHandshake client(
      reinterpret_cast<const UINT8 *>(clientPassword),
      strlen(clientPassword));

    std::vector<UINT8> serverHello;
    std::vector<UINT8> clientResponse;
    std::vector<UINT8> serverFinish;
    std::vector<UINT8> clientActivation;
    server.createHello(&serverHello);
    client.processServerHello(serverHello, &clientResponse);
    server.processClientResponse(clientResponse, &serverFinish, serverKeys);
    client.processServerFinish(serverFinish, clientKeys);
    client.createClientActivation(&clientActivation);
    server.processClientActivation(clientActivation);
  }

  void testAuthenticatedHandshake()
  {
    SecureSessionKeys serverKeys;
    SecureSessionKeys clientKeys;
    runHandshake("correct horse battery staple 2026",
                 "correct horse battery staple 2026",
                 &serverKeys,
                 &clientKeys);

    require(memcmp(serverKeys.clientToServerKey,
                   clientKeys.clientToServerKey,
                   SecureSessionKeys::KEY_SIZE) == 0,
            "client-to-server keys must match");
    require(memcmp(serverKeys.serverToClientKey,
                   clientKeys.serverToClientKey,
                   SecureSessionKeys::KEY_SIZE) == 0,
            "server-to-client keys must match");
    require(memcmp(serverKeys.clientNoncePrefix,
                   clientKeys.clientNoncePrefix,
                   SecureSessionKeys::NONCE_PREFIX_SIZE) == 0,
            "client nonce prefixes must match");
    require(memcmp(serverKeys.serverNoncePrefix,
                   clientKeys.serverNoncePrefix,
                   SecureSessionKeys::NONCE_PREFIX_SIZE) == 0,
            "server nonce prefixes must match");
    require(memcmp(serverKeys.clientToServerKey,
                   serverKeys.serverToClientKey,
                   SecureSessionKeys::KEY_SIZE) != 0,
            "directional traffic keys must be distinct");
  }

  void testWrongPasswordRejected()
  {
    bool rejected = false;
    try {
      SecureSessionKeys serverKeys;
      SecureSessionKeys clientKeys;
      runHandshake("correct encryption password",
                   "incorrect encryption password",
                   &serverKeys,
                   &clientKeys);
    } catch (const IOException &) {
      rejected = true;
    }
    require(rejected, "an incorrect encryption password must be rejected");
  }

  void testServerProofTamperDetection()
  {
    const char password[] = "long dedicated encryption password";
    SecureServerCredentials credentials = SecureServerCredentials::create(
      reinterpret_cast<const UINT8 *>(password),
      strlen(password),
      100000);
    SecureServerHandshake server(credentials);
    SecureClientHandshake client(reinterpret_cast<const UINT8 *>(password),
                                 strlen(password));
    SecureSessionKeys serverKeys;
    SecureSessionKeys clientKeys;

    std::vector<UINT8> serverHello;
    std::vector<UINT8> clientResponse;
    std::vector<UINT8> serverFinish;
    server.createHello(&serverHello);
    client.processServerHello(serverHello, &clientResponse);
    server.processClientResponse(clientResponse, &serverFinish, &serverKeys);
    serverFinish[10] ^= 0x80;

    bool rejected = false;
    try {
      client.processServerFinish(serverFinish, &clientKeys);
    } catch (const IOException &) {
      rejected = true;
    }
    require(rejected, "a modified server proof must be rejected");
  }

  void testActivationProofTamperDetection()
  {
    const char password[] = "long dedicated encryption password";
    SecureServerCredentials credentials = SecureServerCredentials::create(
      reinterpret_cast<const UINT8 *>(password), strlen(password), 100000);
    SecureServerHandshake server(credentials);
    SecureClientHandshake client(reinterpret_cast<const UINT8 *>(password),
                                 strlen(password));
    SecureSessionKeys serverKeys;
    SecureSessionKeys clientKeys;
    std::vector<UINT8> serverHello;
    std::vector<UINT8> clientResponse;
    std::vector<UINT8> serverFinish;
    std::vector<UINT8> clientActivation;

    server.createHello(&serverHello);
    client.processServerHello(serverHello, &clientResponse);
    server.processClientResponse(clientResponse, &serverFinish, &serverKeys);
    client.processServerFinish(serverFinish, &clientKeys);
    client.createClientActivation(&clientActivation);
    clientActivation[12] ^= 0x20;

    bool rejected = false;
    try {
      server.processClientActivation(clientActivation);
    } catch (const IOException &) {
      rejected = true;
    }
    require(rejected, "a modified activation proof must be rejected");
  }

  void testSocketHandshakeAndEncryptedTraffic()
  {
    WSADATA socketData;
    require(WSAStartup(MAKEWORD(2, 2), &socketData) == 0,
            "Winsock startup failed");

    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    require(listener != INVALID_SOCKET, "listener creation failed");
    sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    require(bind(listener, reinterpret_cast<sockaddr *>(&address),
                 sizeof(address)) == 0,
            "listener bind failed");
    require(listen(listener, 1) == 0, "listener start failed");
    int addressLength = sizeof(address);
    require(getsockname(listener, reinterpret_cast<sockaddr *>(&address),
                        &addressLength) == 0,
            "listener address query failed");

    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    require(clientSocket != INVALID_SOCKET, "client socket creation failed");
    require(connect(clientSocket, reinterpret_cast<sockaddr *>(&address),
                    sizeof(address)) == 0,
            "loopback connection failed");
    SOCKET serverSocket = accept(listener, 0, 0);
    closesocket(listener);
    require(serverSocket != INVALID_SOCKET, "server accept failed");

    const char password[] = "socket integration encryption password";
    SecureServerCredentials credentials = SecureServerCredentials::create(
      reinterpret_cast<const UINT8 *>(password), strlen(password), 100000);
    SocketTestChannel serverTransport(serverSocket);
    SocketTestChannel clientTransport(clientSocket);
    SecureChannel serverChannel(&serverTransport);
    SecureChannel clientChannel(&clientTransport);
    DataInputStream serverInput(&serverChannel);
    DataOutputStream serverOutput(&serverChannel);
    DataInputStream clientInput(&clientChannel);
    DataOutputStream clientOutput(&clientChannel);
    std::vector<UINT8> request = makePayload(180000);
    std::vector<UINT8> response = makePayload(90000);
    bool serverSucceeded = false;

    std::thread serverThread([&]() {
      try {
        runSecureServerHandshake(&serverInput, &serverOutput,
                                 &serverChannel, credentials);
        std::vector<UINT8> received(request.size());
        serverInput.readFully(&received.front(), received.size());
        require(received == request,
                "server received corrupted encrypted socket data");
        serverOutput.writeFully(&response.front(), response.size());
        serverOutput.flush();
        serverSucceeded = true;
      } catch (...) {
        serverSucceeded = false;
      }
    });

    runSecureClientHandshake(&clientInput, &clientOutput, &clientChannel,
                             reinterpret_cast<const UINT8 *>(password),
                             strlen(password));
    clientOutput.writeFully(&request.front(), request.size());
    clientOutput.flush();
    std::vector<UINT8> receivedResponse(response.size());
    clientInput.readFully(&receivedResponse.front(), receivedResponse.size());
    serverThread.join();

    require(serverSucceeded, "server socket handshake or traffic failed");
    require(receivedResponse == response,
            "client received corrupted encrypted socket data");
    closesocket(serverSocket);
    closesocket(clientSocket);
    WSACleanup();
  }

  void benchmarkEncryptedChannel()
  {
    const size_t payloadSize = 32 * 1024 * 1024;
    MemoryChannel memory(payloadSize, payloadSize);
    SecureChannel channel(&memory);
    channel.activate(TEST_KEY, TEST_KEY,
                     TEST_NONCE_PREFIX, TEST_NONCE_PREFIX);
    std::vector<UINT8> payload = makePayload(payloadSize);
    std::vector<UINT8> received(payloadSize);

    std::chrono::steady_clock::time_point started =
      std::chrono::steady_clock::now();
    channel.write(&payload.front(), payload.size());
    memory.rewind();
    size_t bytesRead = 0;
    while (bytesRead < received.size()) {
      bytesRead += channel.read(&received[bytesRead],
                                received.size() - bytesRead);
    }
    double seconds = std::chrono::duration<double>(
      std::chrono::steady_clock::now() - started).count();
    double throughput = (payloadSize * 2.0 / (1024.0 * 1024.0)) / seconds;
    require(received == payload, "benchmark encrypted data is corrupted");
    std::cout << "AES-256-GCM memory round-trip: "
              << static_cast<unsigned int>(throughput)
              << " MiB/s" << std::endl;
  }
}

int main()
{
  testPassThrough();
  testEncryptedRoundTrip();
  testTamperDetection();
  testSequenceDetection();
  testAuthenticatedHandshake();
  testWrongPasswordRejected();
  testServerProofTamperDetection();
  testActivationProofTamperDetection();
  testSocketHandshakeAndEncryptedTraffic();
  benchmarkEncryptedChannel();
  std::cout << "SecureChannel tests passed" << std::endl;
  return 0;
}
