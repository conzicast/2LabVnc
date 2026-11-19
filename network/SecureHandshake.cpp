// Copyright (C) 2026.
//
// Windows 7-compatible handshake implementation using only CNG primitives:
// PBKDF2-HMAC-SHA-256, ECDH P-256, SHA-256 and HMAC-SHA-256.

#include "SecureHandshake.h"
#include "SecureChannel.h"

#include <windows.h>
#include <bcrypt.h>
#include <limits>

#include "util/StringStorage.h"

#pragma comment(lib, "bcrypt.lib")

namespace
{
  const size_t SHA256_SIZE = 32;
  const size_t ECDH_PUBLIC_BLOB_SIZE = 72;
  const size_t SERVER_HELLO_SIZE = 132;
  const size_t CLIENT_RESPONSE_WITHOUT_PROOF_SIZE = 108;
  const size_t CLIENT_RESPONSE_SIZE = 140;
  const size_t SERVER_FINISH_SIZE = 36;
  const size_t CLIENT_ACTIVATION_SIZE = 36;
  const UINT32 MIN_PBKDF2_ITERATIONS = 100000;
  const UINT32 MAX_PBKDF2_ITERATIONS = 2000000;

  const UINT8 SERVER_HELLO_MAGIC[4] = { 'T', 'V', 'H', '1' };
  const UINT8 CLIENT_RESPONSE_MAGIC[4] = { 'T', 'V', 'C', '1' };
  const UINT8 SERVER_FINISH_MAGIC[4] = { 'T', 'V', 'S', '1' };
  const UINT8 CLIENT_ACTIVATION_MAGIC[4] = { 'T', 'V', 'A', '1' };

  bool ntSuccess(NTSTATUS status)
  {
    return status >= 0;
  }

  void throwCryptoError(const TCHAR *operation, NTSTATUS status)
  {
    StringStorage message;
    message.format(_T("%s failed with NTSTATUS 0x%08X"),
                   operation, static_cast<UINT32>(status));
    throw IOException(message.getString());
  }

  void requireCryptoSuccess(NTSTATUS status, const TCHAR *operation)
  {
    if (!ntSuccess(status)) {
      throwCryptoError(operation, status);
    }
  }

  void storeUInt32(UINT8 *buffer, UINT32 value)
  {
    buffer[0] = static_cast<UINT8>(value >> 24);
    buffer[1] = static_cast<UINT8>(value >> 16);
    buffer[2] = static_cast<UINT8>(value >> 8);
    buffer[3] = static_cast<UINT8>(value);
  }

  UINT32 loadUInt32(const UINT8 *buffer)
  {
    return (static_cast<UINT32>(buffer[0]) << 24) |
           (static_cast<UINT32>(buffer[1]) << 16) |
           (static_cast<UINT32>(buffer[2]) << 8) |
           static_cast<UINT32>(buffer[3]);
  }

  void appendBytes(std::vector<UINT8> *destination,
                   const void *source,
                   size_t sourceLength)
  {
    const UINT8 *bytes = static_cast<const UINT8 *>(source);
    destination->insert(destination->end(), bytes, bytes + sourceLength);
  }

  void appendLabel(std::vector<UINT8> *destination, const char *label)
  {
    appendBytes(destination, label, strlen(label));
  }

  bool fixedTimeEquals(const UINT8 *left, const UINT8 *right, size_t length)
  {
    UINT8 difference = 0;
    for (size_t index = 0; index < length; ++index) {
      difference |= left[index] ^ right[index];
    }
    return difference == 0;
  }

  void randomBytes(UINT8 *output, size_t outputLength)
  {
    if (outputLength > (std::numeric_limits<ULONG>::max)()) {
      throw IOException(_T("Random output request is too large"));
    }
    requireCryptoSuccess(BCryptGenRandom(0,
                                         output,
                                         static_cast<ULONG>(outputLength),
                                         BCRYPT_USE_SYSTEM_PREFERRED_RNG),
                         _T("BCryptGenRandom"));
  }

  class HashProvider
  {
  public:
    HashProvider(bool hmac)
    : m_algorithm(0),
      m_objectLength(0)
    {
      requireCryptoSuccess(BCryptOpenAlgorithmProvider(
                             &m_algorithm,
                             BCRYPT_SHA256_ALGORITHM,
                             0,
                             hmac ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0),
                           _T("BCryptOpenAlgorithmProvider(SHA-256)"));

      DWORD resultLength = 0;
      NTSTATUS status = BCryptGetProperty(
        m_algorithm,
        BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&m_objectLength),
        sizeof(m_objectLength),
        &resultLength,
        0);
      if (!ntSuccess(status) || resultLength != sizeof(m_objectLength)) {
        BCryptCloseAlgorithmProvider(m_algorithm, 0);
        m_algorithm = 0;
        if (!ntSuccess(status)) {
          throwCryptoError(_T("BCryptGetProperty(ObjectLength)"), status);
        }
        throw IOException(_T("SHA-256 provider returned an invalid object size"));
      }
    }

    ~HashProvider()
    {
      if (m_algorithm != 0) {
        BCryptCloseAlgorithmProvider(m_algorithm, 0);
      }
    }

    BCRYPT_ALG_HANDLE handle() const
    {
      return m_algorithm;
    }

    DWORD objectLength() const
    {
      return m_objectLength;
    }

  private:
    HashProvider(const HashProvider &);
    HashProvider &operator=(const HashProvider &);

    BCRYPT_ALG_HANDLE m_algorithm;
    DWORD m_objectLength;
  };

  void calculateHash(const UINT8 *data,
                     size_t dataLength,
                     UINT8 output[SHA256_SIZE])
  {
    if (dataLength > (std::numeric_limits<ULONG>::max)()) {
      throw IOException(_T("SHA-256 input is too large"));
    }

    HashProvider provider(false);
    std::vector<UINT8> object(provider.objectLength());
    BCRYPT_HASH_HANDLE hash = 0;
    requireCryptoSuccess(BCryptCreateHash(provider.handle(),
                                          &hash,
                                          &object.front(),
                                          static_cast<ULONG>(object.size()),
                                          0,
                                          0,
                                          0),
                         _T("BCryptCreateHash"));
    try {
      requireCryptoSuccess(BCryptHashData(hash,
                                          const_cast<PUCHAR>(data),
                                          static_cast<ULONG>(dataLength),
                                          0),
                           _T("BCryptHashData"));
      requireCryptoSuccess(BCryptFinishHash(hash, output, SHA256_SIZE, 0),
                           _T("BCryptFinishHash"));
    } catch (...) {
      BCryptDestroyHash(hash);
      SecureZeroMemory(&object.front(), object.size());
      throw;
    }
    BCryptDestroyHash(hash);
    SecureZeroMemory(&object.front(), object.size());
  }

  void calculateHmac(const UINT8 *key,
                     size_t keyLength,
                     const UINT8 *data,
                     size_t dataLength,
                     UINT8 output[SHA256_SIZE])
  {
    if (keyLength > (std::numeric_limits<ULONG>::max)() ||
        dataLength > (std::numeric_limits<ULONG>::max)()) {
      throw IOException(_T("HMAC input is too large"));
    }

    HashProvider provider(true);
    std::vector<UINT8> object(provider.objectLength());
    BCRYPT_HASH_HANDLE hash = 0;
    requireCryptoSuccess(BCryptCreateHash(provider.handle(),
                                          &hash,
                                          &object.front(),
                                          static_cast<ULONG>(object.size()),
                                          const_cast<PUCHAR>(key),
                                          static_cast<ULONG>(keyLength),
                                          0),
                         _T("BCryptCreateHash(HMAC)"));
    try {
      requireCryptoSuccess(BCryptHashData(hash,
                                          const_cast<PUCHAR>(data),
                                          static_cast<ULONG>(dataLength),
                                          0),
                           _T("BCryptHashData(HMAC)"));
      requireCryptoSuccess(BCryptFinishHash(hash, output, SHA256_SIZE, 0),
                           _T("BCryptFinishHash(HMAC)"));
    } catch (...) {
      BCryptDestroyHash(hash);
      SecureZeroMemory(&object.front(), object.size());
      throw;
    }
    BCryptDestroyHash(hash);
    SecureZeroMemory(&object.front(), object.size());
  }

  void derivePasswordVerifier(const UINT8 *password,
                              size_t passwordLength,
                              const UINT8 salt[SecureServerCredentials::SALT_SIZE],
                              UINT32 iterations,
                              UINT8 verifier[SecureServerCredentials::VERIFIER_SIZE])
  {
    if (passwordLength == 0) {
      throw IOException(_T("Encryption password cannot be empty"));
    }
    if (passwordLength > (std::numeric_limits<ULONG>::max)()) {
      throw IOException(_T("Encryption password is too large"));
    }
    if (iterations < MIN_PBKDF2_ITERATIONS ||
        iterations > MAX_PBKDF2_ITERATIONS) {
      throw IOException(_T("PBKDF2 iteration count is outside the allowed range"));
    }

    HashProvider provider(true);
    requireCryptoSuccess(BCryptDeriveKeyPBKDF2(
                           provider.handle(),
                           const_cast<PUCHAR>(password),
                           static_cast<ULONG>(passwordLength),
                           const_cast<PUCHAR>(salt),
                           SecureServerCredentials::SALT_SIZE,
                           iterations,
                           verifier,
                           SecureServerCredentials::VERIFIER_SIZE,
                           0),
                         _T("BCryptDeriveKeyPBKDF2"));
  }

  class EcdhKeyPair
  {
  public:
    EcdhKeyPair()
    : m_algorithm(0),
      m_key(0)
    {
      requireCryptoSuccess(BCryptOpenAlgorithmProvider(
                             &m_algorithm,
                             BCRYPT_ECDH_P256_ALGORITHM,
                             0,
                             0),
                           _T("BCryptOpenAlgorithmProvider(ECDH P-256)"));
      try {
        requireCryptoSuccess(BCryptGenerateKeyPair(m_algorithm,
                                                   &m_key,
                                                   256,
                                                   0),
                             _T("BCryptGenerateKeyPair"));
        requireCryptoSuccess(BCryptFinalizeKeyPair(m_key, 0),
                             _T("BCryptFinalizeKeyPair"));
      } catch (...) {
        cleanup();
        throw;
      }
    }

    ~EcdhKeyPair()
    {
      cleanup();
    }

    void exportPublic(std::vector<UINT8> *publicBlob) const
    {
      ULONG requiredSize = 0;
      requireCryptoSuccess(BCryptExportKey(m_key,
                                           0,
                                           BCRYPT_ECCPUBLIC_BLOB,
                                           0,
                                           0,
                                           &requiredSize,
                                           0),
                           _T("BCryptExportKey(size)"));
      if (requiredSize != ECDH_PUBLIC_BLOB_SIZE) {
        throw IOException(_T("Unexpected ECDH P-256 public key size"));
      }
      publicBlob->resize(requiredSize);
      requireCryptoSuccess(BCryptExportKey(m_key,
                                           0,
                                           BCRYPT_ECCPUBLIC_BLOB,
                                           &publicBlob->front(),
                                           requiredSize,
                                           &requiredSize,
                                           0),
                           _T("BCryptExportKey"));
    }

    void derive(const UINT8 *peerPublicBlob,
                size_t peerPublicBlobLength,
                UINT8 output[SHA256_SIZE]) const
    {
      if (peerPublicBlobLength != ECDH_PUBLIC_BLOB_SIZE) {
        throw IOException(_T("Invalid ECDH P-256 public key size"));
      }

      BCRYPT_KEY_HANDLE peerKey = 0;
      BCRYPT_SECRET_HANDLE secret = 0;
      requireCryptoSuccess(BCryptImportKeyPair(
                             m_algorithm,
                             0,
                             BCRYPT_ECCPUBLIC_BLOB,
                             &peerKey,
                             const_cast<PUCHAR>(peerPublicBlob),
                             static_cast<ULONG>(peerPublicBlobLength),
                             0),
                           _T("BCryptImportKeyPair"));
      try {
        requireCryptoSuccess(BCryptSecretAgreement(m_key,
                                                   peerKey,
                                                   &secret,
                                                   0),
                             _T("BCryptSecretAgreement"));

        BCryptBuffer hashBuffer;
        hashBuffer.cbBuffer = sizeof(BCRYPT_SHA256_ALGORITHM);
        hashBuffer.BufferType = KDF_HASH_ALGORITHM;
        hashBuffer.pvBuffer = const_cast<wchar_t *>(BCRYPT_SHA256_ALGORITHM);

        BCryptBufferDesc parameters;
        parameters.ulVersion = BCRYPTBUFFER_VERSION;
        parameters.cBuffers = 1;
        parameters.pBuffers = &hashBuffer;

        ULONG resultLength = 0;
        requireCryptoSuccess(BCryptDeriveKey(secret,
                                             BCRYPT_KDF_HASH,
                                             &parameters,
                                             output,
                                             SHA256_SIZE,
                                             &resultLength,
                                             0),
                             _T("BCryptDeriveKey(ECDH)"));
        if (resultLength != SHA256_SIZE) {
          throw IOException(_T("ECDH key derivation returned an invalid size"));
        }
      } catch (...) {
        if (secret != 0) {
          BCryptDestroySecret(secret);
        }
        BCryptDestroyKey(peerKey);
        throw;
      }
      BCryptDestroySecret(secret);
      BCryptDestroyKey(peerKey);
    }

  private:
    EcdhKeyPair(const EcdhKeyPair &);
    EcdhKeyPair &operator=(const EcdhKeyPair &);

    void cleanup()
    {
      if (m_key != 0) {
        BCryptDestroyKey(m_key);
        m_key = 0;
      }
      if (m_algorithm != 0) {
        BCryptCloseAlgorithmProvider(m_algorithm, 0);
        m_algorithm = 0;
      }
    }

    BCRYPT_ALG_HANDLE m_algorithm;
    BCRYPT_KEY_HANDLE m_key;
  };

  void calculateTranscriptHash(const std::vector<UINT8> &serverHello,
                               const std::vector<UINT8> &clientResponsePrefix,
                               UINT8 output[SHA256_SIZE])
  {
    std::vector<UINT8> transcript(serverHello);
    appendBytes(&transcript,
                &clientResponsePrefix.front(),
                clientResponsePrefix.size());
    calculateHash(&transcript.front(), transcript.size(), output);
  }

  void deriveHandshakeSecret(const UINT8 verifier[SHA256_SIZE],
                             const UINT8 ecdhSecret[SHA256_SIZE],
                             const UINT8 transcriptHash[SHA256_SIZE],
                             UINT8 handshakeSecret[SHA256_SIZE])
  {
    std::vector<UINT8> input;
    appendLabel(&input, "2LabVnc handshake v2");
    appendBytes(&input, ecdhSecret, SHA256_SIZE);
    appendBytes(&input, transcriptHash, SHA256_SIZE);
    calculateHmac(verifier, SHA256_SIZE,
                  &input.front(), input.size(), handshakeSecret);
  }

  void deriveProof(const UINT8 handshakeSecret[SHA256_SIZE],
                   const char *label,
                   const UINT8 transcriptHash[SHA256_SIZE],
                   UINT8 proof[SHA256_SIZE])
  {
    std::vector<UINT8> input;
    appendLabel(&input, label);
    appendBytes(&input, transcriptHash, SHA256_SIZE);
    calculateHmac(handshakeSecret, SHA256_SIZE,
                  &input.front(), input.size(), proof);
  }

  void expandKey(const UINT8 handshakeSecret[SHA256_SIZE],
                 const char *label,
                 const UINT8 transcriptHash[SHA256_SIZE],
                 UINT8 output[SHA256_SIZE])
  {
    std::vector<UINT8> input;
    appendLabel(&input, label);
    appendBytes(&input, transcriptHash, SHA256_SIZE);
    calculateHmac(handshakeSecret, SHA256_SIZE,
                  &input.front(), input.size(), output);
  }

  void deriveSessionKeys(const UINT8 handshakeSecret[SHA256_SIZE],
                         const UINT8 transcriptHash[SHA256_SIZE],
                         SecureSessionKeys *sessionKeys)
  {
    expandKey(handshakeSecret, "client to server key", transcriptHash,
              sessionKeys->clientToServerKey);
    expandKey(handshakeSecret, "server to client key", transcriptHash,
              sessionKeys->serverToClientKey);

    UINT8 nonceMaterial[SHA256_SIZE];
    expandKey(handshakeSecret, "client nonce", transcriptHash, nonceMaterial);
    memcpy(sessionKeys->clientNoncePrefix, nonceMaterial,
           SecureSessionKeys::NONCE_PREFIX_SIZE);
    expandKey(handshakeSecret, "server nonce", transcriptHash, nonceMaterial);
    memcpy(sessionKeys->serverNoncePrefix, nonceMaterial,
           SecureSessionKeys::NONCE_PREFIX_SIZE);
    SecureZeroMemory(nonceMaterial, sizeof(nonceMaterial));
  }
}

class SecureServerHandshakeImpl
{
public:
  SecureServerHandshakeImpl(const SecureServerCredentials &sourceCredentials)
  : credentials(sourceCredentials),
    keyPair(0),
    helloCreated(false),
    completed(false),
    activationVerified(false),
    viewOnly(true)
  {
    memset(handshakeSecret, 0, sizeof(handshakeSecret));
    memset(transcriptHash, 0, sizeof(transcriptHash));
  }

  ~SecureServerHandshakeImpl()
  {
    delete keyPair;
    SecureZeroMemory(&credentials, sizeof(credentials));
    SecureZeroMemory(handshakeSecret, sizeof(handshakeSecret));
    SecureZeroMemory(transcriptHash, sizeof(transcriptHash));
  }

  SecureServerCredentials credentials;
  EcdhKeyPair *keyPair;
  std::vector<UINT8> serverHello;
  UINT8 handshakeSecret[SHA256_SIZE];
  UINT8 transcriptHash[SHA256_SIZE];
  bool helloCreated;
  bool completed;
  bool activationVerified;
  bool viewOnly;
};

class SecureClientHandshakeImpl
{
public:
  SecureClientHandshakeImpl(const UINT8 *sourcePassword, size_t passwordLength)
  : keyPair(0),
    responseCreated(false),
    completed(false),
    activationCreated(false)
  {
    if (sourcePassword == 0 || passwordLength == 0) {
      throw IOException(_T("Encryption password cannot be empty"));
    }
    password.assign(sourcePassword, sourcePassword + passwordLength);
    memset(handshakeSecret, 0, sizeof(handshakeSecret));
    memset(transcriptHash, 0, sizeof(transcriptHash));
  }

  ~SecureClientHandshakeImpl()
  {
    delete keyPair;
    if (!password.empty()) {
      SecureZeroMemory(&password.front(), password.size());
    }
    SecureZeroMemory(handshakeSecret, sizeof(handshakeSecret));
    SecureZeroMemory(transcriptHash, sizeof(transcriptHash));
  }

  std::vector<UINT8> password;
  EcdhKeyPair *keyPair;
  UINT8 handshakeSecret[SHA256_SIZE];
  UINT8 transcriptHash[SHA256_SIZE];
  bool responseCreated;
  bool completed;
  bool activationCreated;
};

SecureServerCredentials::SecureServerCredentials()
: iterations(0)
{
  memset(salt, 0, sizeof(salt));
  memset(verifier, 0, sizeof(verifier));
  memset(viewOnlyVerifier, 0, sizeof(viewOnlyVerifier));
}

SecureServerCredentials SecureServerCredentials::create(
  const UINT8 *password,
  size_t passwordLength,
  UINT32 iterationCount)
{
  SecureServerCredentials credentials;
  if (passwordLength < MIN_PASSWORD_LENGTH) {
    throw IOException(_T("The full-control password must contain at least 16 characters"));
  }
  randomBytes(credentials.salt, sizeof(credentials.salt));
  credentials.iterations = iterationCount;
  derivePasswordVerifier(password, passwordLength,
                         credentials.salt, credentials.iterations,
                         credentials.verifier);
  return credentials;
}

void SecureServerCredentials::setViewOnlyPassword(const UINT8 *password,
                                                  size_t passwordLength)
{
  if (passwordLength < MIN_PASSWORD_LENGTH) {
    throw IOException(_T("The view-only password must contain at least 16 characters"));
  }
  derivePasswordVerifier(password, passwordLength, salt, iterations,
                         viewOnlyVerifier);
}

bool SecureServerCredentials::hasDistinctPasswords() const
{
  const UINT8 emptyVerifier[VERIFIER_SIZE] = {};
  return iterations >= MIN_PBKDF2_ITERATIONS &&
         iterations <= MAX_PBKDF2_ITERATIONS &&
         !fixedTimeEquals(verifier, emptyVerifier, VERIFIER_SIZE) &&
         !fixedTimeEquals(viewOnlyVerifier, emptyVerifier, VERIFIER_SIZE) &&
         !fixedTimeEquals(verifier, viewOnlyVerifier, VERIFIER_SIZE);
}

SecureSessionKeys::SecureSessionKeys()
{
  memset(this, 0, sizeof(*this));
}

SecureSessionKeys::~SecureSessionKeys()
{
  SecureZeroMemory(this, sizeof(*this));
}

SecureServerHandshake::SecureServerHandshake(
  const SecureServerCredentials &credentials)
: m_impl(new SecureServerHandshakeImpl(credentials))
{
  if (!credentials.hasDistinctPasswords()) {
    delete m_impl;
    m_impl = 0;
    throw IOException(_T("Stored encryption credentials are invalid"));
  }
}

SecureServerHandshake::~SecureServerHandshake()
{
  delete m_impl;
}

void SecureServerHandshake::createHello(std::vector<UINT8> *serverHello)
{
  if (m_impl->helloCreated || serverHello == 0) {
    throw IOException(_T("Invalid server handshake state"));
  }

  m_impl->keyPair = new EcdhKeyPair();
  std::vector<UINT8> publicBlob;
  m_impl->keyPair->exportPublic(&publicBlob);

  m_impl->serverHello.resize(SERVER_HELLO_SIZE);
  UINT8 *message = &m_impl->serverHello.front();
  memcpy(message, SERVER_HELLO_MAGIC, sizeof(SERVER_HELLO_MAGIC));
  storeUInt32(message + 4, m_impl->credentials.iterations);
  memcpy(message + 8, m_impl->credentials.salt,
         SecureServerCredentials::SALT_SIZE);
  randomBytes(message + 24, 32);
  memcpy(message + 56, &publicBlob.front(), publicBlob.size());

  *serverHello = m_impl->serverHello;
  m_impl->helloCreated = true;
}

void SecureServerHandshake::processClientResponse(
  const std::vector<UINT8> &clientResponse,
  std::vector<UINT8> *serverFinish,
  SecureSessionKeys *sessionKeys)
{
  if (!m_impl->helloCreated || m_impl->completed ||
      serverFinish == 0 || sessionKeys == 0 ||
      clientResponse.size() != CLIENT_RESPONSE_SIZE) {
    throw IOException(_T("Invalid client handshake response"));
  }
  if (memcmp(&clientResponse.front(), CLIENT_RESPONSE_MAGIC,
             sizeof(CLIENT_RESPONSE_MAGIC)) != 0) {
    throw IOException(_T("Invalid client handshake marker"));
  }

  std::vector<UINT8> responsePrefix(clientResponse.begin(),
                                    clientResponse.begin() +
                                    CLIENT_RESPONSE_WITHOUT_PROOF_SIZE);
  calculateTranscriptHash(m_impl->serverHello, responsePrefix,
                          m_impl->transcriptHash);

  // Check both proofs before choosing a role. The client supplies no role flag.
  SecureSessionKeys scratch;
  UINT8 *ecdhSecret = scratch.clientToServerKey;
  UINT8 *viewOnlySecret = scratch.serverToClientKey;
  m_impl->keyPair->derive(&clientResponse[36], ECDH_PUBLIC_BLOB_SIZE,
                          ecdhSecret);
  deriveHandshakeSecret(m_impl->credentials.verifier,
                        ecdhSecret,
                        m_impl->transcriptHash,
                        m_impl->handshakeSecret);
  deriveHandshakeSecret(m_impl->credentials.viewOnlyVerifier,
                        ecdhSecret,
                        m_impl->transcriptHash,
                        viewOnlySecret);

  UINT8 expectedProof[SHA256_SIZE];
  deriveProof(m_impl->handshakeSecret, "client proof",
              m_impl->transcriptHash, expectedProof);
  bool fullControlValid = fixedTimeEquals(expectedProof,
                                    &clientResponse[CLIENT_RESPONSE_WITHOUT_PROOF_SIZE],
                                    sizeof(expectedProof));
  deriveProof(viewOnlySecret, "client proof",
              m_impl->transcriptHash, expectedProof);
  bool viewOnlyValid = fixedTimeEquals(expectedProof,
                                      &clientResponse[CLIENT_RESPONSE_WITHOUT_PROOF_SIZE],
                                      sizeof(expectedProof));
  SecureZeroMemory(expectedProof, sizeof(expectedProof));
  if (fullControlValid == viewOnlyValid) {
    throw SecurePasswordException();
  }
  m_impl->viewOnly = viewOnlyValid;
  if (viewOnlyValid) {
    memcpy(m_impl->handshakeSecret, viewOnlySecret, SHA256_SIZE);
  }

  serverFinish->resize(SERVER_FINISH_SIZE);
  memcpy(&serverFinish->front(), SERVER_FINISH_MAGIC,
         sizeof(SERVER_FINISH_MAGIC));
  deriveProof(m_impl->handshakeSecret, "server proof",
              m_impl->transcriptHash, &(*serverFinish)[4]);
  deriveSessionKeys(m_impl->handshakeSecret,
                    m_impl->transcriptHash,
                    sessionKeys);
  m_impl->completed = true;
}

SecureClientHandshake::SecureClientHandshake(const UINT8 *password,
                                             size_t passwordLength)
: m_impl(new SecureClientHandshakeImpl(password, passwordLength))
{
}

SecureClientHandshake::~SecureClientHandshake()
{
  delete m_impl;
}

void SecureClientHandshake::processServerHello(
  const std::vector<UINT8> &serverHello,
  std::vector<UINT8> *clientResponse)
{
  if (m_impl->responseCreated || clientResponse == 0 ||
      serverHello.size() != SERVER_HELLO_SIZE) {
    throw IOException(_T("Invalid server handshake message"));
  }
  if (memcmp(&serverHello.front(), SERVER_HELLO_MAGIC,
             sizeof(SERVER_HELLO_MAGIC)) != 0) {
    throw IOException(_T("Invalid server handshake marker"));
  }

  UINT32 iterations = loadUInt32(&serverHello[4]);
  UINT8 verifier[SHA256_SIZE];
  derivePasswordVerifier(&m_impl->password.front(), m_impl->password.size(),
                         &serverHello[8], iterations, verifier);

  m_impl->keyPair = new EcdhKeyPair();
  std::vector<UINT8> publicBlob;
  m_impl->keyPair->exportPublic(&publicBlob);

  clientResponse->resize(CLIENT_RESPONSE_SIZE);
  UINT8 *response = &clientResponse->front();
  memcpy(response, CLIENT_RESPONSE_MAGIC, sizeof(CLIENT_RESPONSE_MAGIC));
  randomBytes(response + 4, 32);
  memcpy(response + 36, &publicBlob.front(), publicBlob.size());

  std::vector<UINT8> responsePrefix(clientResponse->begin(),
                                    clientResponse->begin() +
                                    CLIENT_RESPONSE_WITHOUT_PROOF_SIZE);
  calculateTranscriptHash(serverHello, responsePrefix,
                          m_impl->transcriptHash);

  UINT8 ecdhSecret[SHA256_SIZE];
  m_impl->keyPair->derive(&serverHello[56], ECDH_PUBLIC_BLOB_SIZE,
                          ecdhSecret);
  deriveHandshakeSecret(verifier,
                        ecdhSecret,
                        m_impl->transcriptHash,
                        m_impl->handshakeSecret);
  SecureZeroMemory(verifier, sizeof(verifier));
  SecureZeroMemory(ecdhSecret, sizeof(ecdhSecret));

  deriveProof(m_impl->handshakeSecret, "client proof",
              m_impl->transcriptHash,
              response + CLIENT_RESPONSE_WITHOUT_PROOF_SIZE);
  m_impl->responseCreated = true;
}

void SecureClientHandshake::processServerFinish(
  const std::vector<UINT8> &serverFinish,
  SecureSessionKeys *sessionKeys)
{
  if (!m_impl->responseCreated || m_impl->completed || sessionKeys == 0 ||
      serverFinish.size() != SERVER_FINISH_SIZE) {
    throw IOException(_T("Invalid server handshake completion"));
  }
  if (memcmp(&serverFinish.front(), SERVER_FINISH_MAGIC,
             sizeof(SERVER_FINISH_MAGIC)) != 0) {
    throw IOException(_T("Invalid server handshake completion marker"));
  }

  UINT8 expectedProof[SHA256_SIZE];
  deriveProof(m_impl->handshakeSecret, "server proof",
              m_impl->transcriptHash, expectedProof);
  bool proofValid = fixedTimeEquals(expectedProof,
                                    &serverFinish[4],
                                    sizeof(expectedProof));
  SecureZeroMemory(expectedProof, sizeof(expectedProof));
  if (!proofValid) {
    throw IOException(_T("Secure server authentication failed"));
  }

  deriveSessionKeys(m_impl->handshakeSecret,
                    m_impl->transcriptHash,
                    sessionKeys);
  m_impl->completed = true;
}

bool SecureServerHandshake::processClientActivation(
  const std::vector<UINT8> &clientActivation)
{
  if (!m_impl->completed || m_impl->activationVerified ||
      clientActivation.size() != CLIENT_ACTIVATION_SIZE ||
      memcmp(&clientActivation.front(), CLIENT_ACTIVATION_MAGIC,
             sizeof(CLIENT_ACTIVATION_MAGIC)) != 0) {
    throw IOException(_T("Invalid secure channel activation message"));
  }

  UINT8 expectedProof[SHA256_SIZE];
  deriveProof(m_impl->handshakeSecret, "client activation",
              m_impl->transcriptHash, expectedProof);
  bool proofValid = fixedTimeEquals(expectedProof, &clientActivation[4],
                                    sizeof(expectedProof));
  SecureZeroMemory(expectedProof, sizeof(expectedProof));
  if (!proofValid) {
    throw IOException(_T("Secure channel activation authentication failed"));
  }
  m_impl->activationVerified = true;
  return m_impl->viewOnly;
}

void SecureClientHandshake::createClientActivation(
  std::vector<UINT8> *clientActivation)
{
  if (!m_impl->completed || m_impl->activationCreated ||
      clientActivation == 0) {
    throw IOException(_T("Invalid client secure channel activation state"));
  }
  clientActivation->resize(CLIENT_ACTIVATION_SIZE);
  memcpy(&clientActivation->front(), CLIENT_ACTIVATION_MAGIC,
         sizeof(CLIENT_ACTIVATION_MAGIC));
  deriveProof(m_impl->handshakeSecret, "client activation",
              m_impl->transcriptHash, &(*clientActivation)[4]);
  m_impl->activationCreated = true;
}

bool runSecureServerHandshake(DataInputStream *input,
                              DataOutputStream *output,
                              SecureChannel *channel,
                              const SecureServerCredentials &credentials)
{
  if (input == 0 || output == 0 || channel == 0) {
    throw IOException(_T("Secure server handshake has an invalid stream"));
  }

  SecureServerHandshake handshake(credentials);
  SecureSessionKeys keys;
  std::vector<UINT8> serverHello;
  std::vector<UINT8> clientResponse(CLIENT_RESPONSE_SIZE);
  std::vector<UINT8> serverFinish;
  std::vector<UINT8> clientActivation(CLIENT_ACTIVATION_SIZE);

  handshake.createHello(&serverHello);
  output->writeFully(&serverHello.front(), serverHello.size());
  output->flush();
  input->readFully(&clientResponse.front(), clientResponse.size());
  handshake.processClientResponse(clientResponse, &serverFinish, &keys);
  output->writeFully(&serverFinish.front(), serverFinish.size());
  output->flush();
  input->readFully(&clientActivation.front(), clientActivation.size());
  const bool viewOnly = handshake.processClientActivation(clientActivation);

  channel->activate(keys.serverToClientKey,
                    keys.clientToServerKey,
                    keys.serverNoncePrefix,
                    keys.clientNoncePrefix);
  return viewOnly;
}

void runSecureClientHandshake(DataInputStream *input,
                              DataOutputStream *output,
                              SecureChannel *channel,
                              const UINT8 *password,
                              size_t passwordLength)
{
  if (input == 0 || output == 0 || channel == 0) {
    throw IOException(_T("Secure client handshake has an invalid stream"));
  }

  SecureClientHandshake handshake(password, passwordLength);
  SecureSessionKeys keys;
  std::vector<UINT8> serverHello(SERVER_HELLO_SIZE);
  std::vector<UINT8> clientResponse;
  std::vector<UINT8> serverFinish(SERVER_FINISH_SIZE);
  std::vector<UINT8> clientActivation;

  input->readFully(&serverHello.front(), serverHello.size());
  handshake.processServerHello(serverHello, &clientResponse);
  output->writeFully(&clientResponse.front(), clientResponse.size());
  output->flush();
  input->readFully(&serverFinish.front(), serverFinish.size());
  handshake.processServerFinish(serverFinish, &keys);
  handshake.createClientActivation(&clientActivation);
  output->writeFully(&clientActivation.front(), clientActivation.size());
  output->flush();

  channel->activate(keys.clientToServerKey,
                    keys.serverToClientKey,
                    keys.clientNoncePrefix,
                    keys.serverNoncePrefix);
}
