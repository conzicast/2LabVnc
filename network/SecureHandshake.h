// Copyright (C) 2026.
//
// Password-authenticated handshake support for SecureChannel. The protocol
// combines a PBKDF2 verifier with ephemeral ECDH P-256 and authenticates the
// full transcript before exposing directional session keys.

#ifndef _SECURE_HANDSHAKE_H_
#define _SECURE_HANDSHAKE_H_

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <vector>

#include "io-lib/IOException.h"
#include "io-lib/DataInputStream.h"
#include "io-lib/DataOutputStream.h"
#include "util/inttypes.h"

class SecureChannel;

class SecurePasswordException : public IOException
{
public:
  SecurePasswordException() : IOException(_T("2LabVnc password authentication failed")) {}
};

struct SecureServerCredentials
{
  static const size_t SALT_SIZE = 16;
  static const size_t VERIFIER_SIZE = 32;

  SecureServerCredentials();

  static SecureServerCredentials create(const UINT8 *password,
                                        size_t passwordLength,
                                        UINT32 iterations);
  void setViewOnlyPassword(const UINT8 *password, size_t passwordLength);
  bool hasDistinctPasswords() const;
  static const size_t MIN_PASSWORD_LENGTH = 16;
  static const size_t MAX_PASSWORD_LENGTH = 128;
  static const UINT32 DEFAULT_ITERATIONS = 200000;

  UINT8 salt[SALT_SIZE];
  UINT8 verifier[VERIFIER_SIZE];
  UINT8 viewOnlyVerifier[VERIFIER_SIZE];
  UINT32 iterations;
};

struct SecureSessionKeys
{
  static const size_t KEY_SIZE = 32;
  static const size_t NONCE_PREFIX_SIZE = 4;

  SecureSessionKeys();
  ~SecureSessionKeys();

  UINT8 clientToServerKey[KEY_SIZE];
  UINT8 serverToClientKey[KEY_SIZE];
  UINT8 clientNoncePrefix[NONCE_PREFIX_SIZE];
  UINT8 serverNoncePrefix[NONCE_PREFIX_SIZE];
};

class SecureServerHandshakeImpl;

class SecureServerHandshake
{
public:
  SecureServerHandshake(const SecureServerCredentials &credentials);
  ~SecureServerHandshake();

  void createHello(std::vector<UINT8> *serverHello);
  void processClientResponse(const std::vector<UINT8> &clientResponse,
                             std::vector<UINT8> *serverFinish,
                             SecureSessionKeys *sessionKeys);
  bool processClientActivation(const std::vector<UINT8> &clientActivation);

private:
  SecureServerHandshake(const SecureServerHandshake &);
  SecureServerHandshake &operator=(const SecureServerHandshake &);

  SecureServerHandshakeImpl *m_impl;
};

class SecureClientHandshakeImpl;

class SecureClientHandshake
{
public:
  SecureClientHandshake(const UINT8 *password, size_t passwordLength);
  ~SecureClientHandshake();

  void processServerHello(const std::vector<UINT8> &serverHello,
                          std::vector<UINT8> *clientResponse);
  void processServerFinish(const std::vector<UINT8> &serverFinish,
                           SecureSessionKeys *sessionKeys);
  void createClientActivation(std::vector<UINT8> *clientActivation);

private:
  SecureClientHandshake(const SecureClientHandshake &);
  SecureClientHandshake &operator=(const SecureClientHandshake &);

  SecureClientHandshakeImpl *m_impl;
};

// Returns true only for an authenticated view-only session.
bool runSecureServerHandshake(DataInputStream *input,
                              DataOutputStream *output,
                              SecureChannel *channel,
                              const SecureServerCredentials &credentials);

void runSecureClientHandshake(DataInputStream *input,
                              DataOutputStream *output,
                              SecureChannel *channel,
                              const UINT8 *password,
                              size_t passwordLength);

#endif // _SECURE_HANDSHAKE_H_
