// Copyright (C) 2026.
//
// AES-256-GCM record transport for Windows 7 and later. Cryptographic
// operations are delegated to Windows CNG; this file does not implement any
// cryptographic primitive.

#include "SecureChannel.h"

#include <algorithm>
#include <limits>
#include <windows.h>
#include <bcrypt.h>

#include "util/StringStorage.h"

#pragma comment(lib, "bcrypt.lib")

namespace
{
  const size_t RECORD_HEADER_SIZE = 16;
  const size_t AUTH_TAG_SIZE = 16;
  const size_t MAX_PLAINTEXT_SIZE = 64 * 1024;
  const UINT8 RECORD_MAGIC[4] = { 'T', 'V', 'E', '1' };

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

  void storeUInt64(UINT8 *buffer, UINT64 value)
  {
    for (size_t index = 0; index < 8; ++index) {
      buffer[index] = static_cast<UINT8>(value >> ((7 - index) * 8));
    }
  }

  UINT64 loadUInt64(const UINT8 *buffer)
  {
    UINT64 value = 0;
    for (size_t index = 0; index < 8; ++index) {
      value = (value << 8) | buffer[index];
    }
    return value;
  }

  void buildNonce(UINT8 nonce[12], const UINT8 prefix[4], UINT64 sequence)
  {
    memcpy(nonce, prefix, 4);
    storeUInt64(nonce + 4, sequence);
  }
}

class AesGcmState
{
public:
  AesGcmState(const UINT8 key[SecureChannel::KEY_SIZE],
              const UINT8 noncePrefix[SecureChannel::NONCE_PREFIX_SIZE])
  : m_algorithm(0),
    m_key(0)
  {
    memcpy(m_noncePrefix, noncePrefix, sizeof(m_noncePrefix));

    NTSTATUS status = BCryptOpenAlgorithmProvider(&m_algorithm,
                                                   BCRYPT_AES_ALGORITHM,
                                                   0,
                                                   0);
    if (!ntSuccess(status)) {
      throwCryptoError(_T("BCryptOpenAlgorithmProvider"), status);
    }

    try {
      status = BCryptSetProperty(m_algorithm,
                                 BCRYPT_CHAINING_MODE,
                                 reinterpret_cast<PUCHAR>(BCRYPT_CHAIN_MODE_GCM),
                                 sizeof(BCRYPT_CHAIN_MODE_GCM),
                                 0);
      if (!ntSuccess(status)) {
        throwCryptoError(_T("BCryptSetProperty(GCM)"), status);
      }

      DWORD keyObjectSize = 0;
      DWORD resultSize = 0;
      status = BCryptGetProperty(m_algorithm,
                                 BCRYPT_OBJECT_LENGTH,
                                 reinterpret_cast<PUCHAR>(&keyObjectSize),
                                 sizeof(keyObjectSize),
                                 &resultSize,
                                 0);
      if (!ntSuccess(status) || resultSize != sizeof(keyObjectSize)) {
        if (ntSuccess(status)) {
          throw IOException(_T("BCryptGetProperty returned an invalid key object size"));
        }
        throwCryptoError(_T("BCryptGetProperty(ObjectLength)"), status);
      }

      BCRYPT_AUTH_TAG_LENGTHS_STRUCT tagLengths;
      status = BCryptGetProperty(m_algorithm,
                                 BCRYPT_AUTH_TAG_LENGTH,
                                 reinterpret_cast<PUCHAR>(&tagLengths),
                                 sizeof(tagLengths),
                                 &resultSize,
                                 0);
      if (!ntSuccess(status)) {
        throwCryptoError(_T("BCryptGetProperty(AuthTagLength)"), status);
      }
      if (AUTH_TAG_SIZE < tagLengths.dwMinLength ||
          AUTH_TAG_SIZE > tagLengths.dwMaxLength) {
        throw IOException(_T("The AES-GCM provider does not support 16-byte tags"));
      }

      m_keyObject.resize(keyObjectSize);
      status = BCryptGenerateSymmetricKey(m_algorithm,
                                          &m_key,
                                          &m_keyObject.front(),
                                          keyObjectSize,
                                          const_cast<PUCHAR>(key),
                                          SecureChannel::KEY_SIZE,
                                          0);
      if (!ntSuccess(status)) {
        throwCryptoError(_T("BCryptGenerateSymmetricKey"), status);
      }
    } catch (...) {
      cleanup();
      throw;
    }
  }

  ~AesGcmState()
  {
    cleanup();
    SecureZeroMemory(m_noncePrefix, sizeof(m_noncePrefix));
  }

  void encrypt(const UINT8 *plaintext,
               size_t plaintextLength,
               const UINT8 *authenticatedData,
               size_t authenticatedDataLength,
               UINT64 sequence,
               std::vector<UINT8> *ciphertext,
               UINT8 tag[AUTH_TAG_SIZE])
  {
    validateLengths(plaintextLength, authenticatedDataLength);
    ciphertext->resize(plaintextLength);

    UINT8 nonce[12];
    buildNonce(nonce, m_noncePrefix, sequence);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = sizeof(nonce);
    authInfo.pbAuthData = const_cast<PUCHAR>(authenticatedData);
    authInfo.cbAuthData = static_cast<ULONG>(authenticatedDataLength);
    authInfo.pbTag = tag;
    authInfo.cbTag = AUTH_TAG_SIZE;

    ULONG resultSize = 0;
    NTSTATUS status = BCryptEncrypt(m_key,
                                    const_cast<PUCHAR>(plaintext),
                                    static_cast<ULONG>(plaintextLength),
                                    &authInfo,
                                    0,
                                    0,
                                    ciphertext->empty() ? 0 : &ciphertext->front(),
                                    static_cast<ULONG>(ciphertext->size()),
                                    &resultSize,
                                    0);
    SecureZeroMemory(nonce, sizeof(nonce));
    if (!ntSuccess(status)) {
      throwCryptoError(_T("BCryptEncrypt(AES-GCM)"), status);
    }
    if (resultSize != plaintextLength) {
      throw IOException(_T("AES-GCM encryption returned an unexpected length"));
    }
  }

  void decrypt(const UINT8 *ciphertext,
               size_t ciphertextLength,
               const UINT8 *authenticatedData,
               size_t authenticatedDataLength,
               UINT64 sequence,
               const UINT8 tag[AUTH_TAG_SIZE],
               std::vector<UINT8> *plaintext)
  {
    validateLengths(ciphertextLength, authenticatedDataLength);
    plaintext->resize(ciphertextLength);

    UINT8 nonce[12];
    buildNonce(nonce, m_noncePrefix, sequence);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = sizeof(nonce);
    authInfo.pbAuthData = const_cast<PUCHAR>(authenticatedData);
    authInfo.cbAuthData = static_cast<ULONG>(authenticatedDataLength);
    authInfo.pbTag = const_cast<PUCHAR>(tag);
    authInfo.cbTag = AUTH_TAG_SIZE;

    ULONG resultSize = 0;
    NTSTATUS status = BCryptDecrypt(m_key,
                                    const_cast<PUCHAR>(ciphertext),
                                    static_cast<ULONG>(ciphertextLength),
                                    &authInfo,
                                    0,
                                    0,
                                    plaintext->empty() ? 0 : &plaintext->front(),
                                    static_cast<ULONG>(plaintext->size()),
                                    &resultSize,
                                    0);
    SecureZeroMemory(nonce, sizeof(nonce));
    if (!ntSuccess(status)) {
      plaintext->clear();
      throw IOException(_T("Encrypted record authentication failed"));
    }
    if (resultSize != ciphertextLength) {
      plaintext->clear();
      throw IOException(_T("AES-GCM decryption returned an unexpected length"));
    }
  }

private:
  AesGcmState(const AesGcmState &);
  AesGcmState &operator=(const AesGcmState &);

  void validateLengths(size_t dataLength, size_t authenticatedDataLength)
  {
    if (dataLength > (std::numeric_limits<ULONG>::max)() ||
        authenticatedDataLength > (std::numeric_limits<ULONG>::max)()) {
      throw IOException(_T("AES-GCM input is too large"));
    }
  }

  void cleanup()
  {
    if (m_key != 0) {
      BCryptDestroyKey(m_key);
      m_key = 0;
    }
    if (!m_keyObject.empty()) {
      SecureZeroMemory(&m_keyObject.front(), m_keyObject.size());
      m_keyObject.clear();
    }
    if (m_algorithm != 0) {
      BCryptCloseAlgorithmProvider(m_algorithm, 0);
      m_algorithm = 0;
    }
  }

  BCRYPT_ALG_HANDLE m_algorithm;
  BCRYPT_KEY_HANDLE m_key;
  std::vector<UINT8> m_keyObject;
  UINT8 m_noncePrefix[SecureChannel::NONCE_PREFIX_SIZE];
};

SecureChannel::SecureChannel(Channel *channel)
: m_channel(channel),
  m_sendCipher(0),
  m_receiveCipher(0),
  m_active(false),
  m_sendSequence(0),
  m_receiveSequence(0),
  m_plaintextPosition(0)
{
  if (m_channel == 0) {
    throw IOException(_T("SecureChannel requires a valid underlying channel"));
  }
}

SecureChannel::~SecureChannel()
{
  delete m_sendCipher;
  delete m_receiveCipher;
  if (!m_plaintext.empty()) {
    SecureZeroMemory(&m_plaintext.front(), m_plaintext.size());
  }
}

void SecureChannel::activate(const UINT8 sendKey[KEY_SIZE],
                             const UINT8 receiveKey[KEY_SIZE],
                             const UINT8 sendNoncePrefix[NONCE_PREFIX_SIZE],
                             const UINT8 receiveNoncePrefix[NONCE_PREFIX_SIZE])
{
  if (m_active || m_sendCipher != 0 || m_receiveCipher != 0) {
    throw IOException(_T("SecureChannel is already active"));
  }
  if (sendKey == 0 || receiveKey == 0 ||
      sendNoncePrefix == 0 || receiveNoncePrefix == 0) {
    throw IOException(_T("SecureChannel activation data is incomplete"));
  }

  AesGcmState *sendCipher = new AesGcmState(sendKey, sendNoncePrefix);
  try {
    m_receiveCipher = new AesGcmState(receiveKey, receiveNoncePrefix);
  } catch (...) {
    delete sendCipher;
    throw;
  }
  m_sendCipher = sendCipher;
  m_sendSequence = 0;
  m_receiveSequence = 0;
  m_active = true;
}

bool SecureChannel::isActive() const
{
  return m_active;
}

size_t SecureChannel::read(void *buffer, size_t length)
{
  if (!m_active) {
    return m_channel->read(buffer, length);
  }
  if (length == 0) {
    return 0;
  }
  if (m_plaintextPosition == m_plaintext.size()) {
    readNextRecord();
  }

  size_t availableBytes = m_plaintext.size() - m_plaintextPosition;
  size_t bytesToCopy = std::min(length, availableBytes);
  memcpy(buffer, &m_plaintext[m_plaintextPosition], bytesToCopy);
  m_plaintextPosition += bytesToCopy;

  if (m_plaintextPosition == m_plaintext.size()) {
    SecureZeroMemory(&m_plaintext.front(), m_plaintext.size());
    m_plaintext.clear();
    m_plaintextPosition = 0;
  }
  return bytesToCopy;
}

size_t SecureChannel::write(const void *buffer, size_t length)
{
  if (!m_active) {
    return m_channel->write(buffer, length);
  }
  if (length == 0) {
    return 0;
  }

  const UINT8 *plaintext = static_cast<const UINT8 *>(buffer);
  size_t totalWritten = 0;
  while (totalWritten < length) {
    if (m_sendSequence == (std::numeric_limits<UINT64>::max)()) {
      throw IOException(_T("SecureChannel send sequence is exhausted"));
    }

    size_t recordLength = std::min(length - totalWritten, MAX_PLAINTEXT_SIZE);
    UINT8 header[RECORD_HEADER_SIZE];
    memcpy(header, RECORD_MAGIC, sizeof(RECORD_MAGIC));
    storeUInt32(header + 4, static_cast<UINT32>(recordLength));
    storeUInt64(header + 8, m_sendSequence);

    std::vector<UINT8> ciphertext;
    UINT8 tag[AUTH_TAG_SIZE];
    m_sendCipher->encrypt(plaintext + totalWritten,
                          recordLength,
                          header,
                          sizeof(header),
                          m_sendSequence,
                          &ciphertext,
                          tag);

    writeFully(header, sizeof(header));
    writeFully(&ciphertext.front(), ciphertext.size());
    writeFully(tag, sizeof(tag));

    SecureZeroMemory(tag, sizeof(tag));
    ++m_sendSequence;
    totalWritten += recordLength;
  }
  return length;
}

size_t SecureChannel::available()
{
  if (!m_active) {
    return m_channel->available();
  }
  if (m_plaintextPosition < m_plaintext.size()) {
    return m_plaintext.size() - m_plaintextPosition;
  }
  return 0;
}

void SecureChannel::close()
{
  m_channel->close();
}

void SecureChannel::readNextRecord()
{
  if (m_receiveSequence == (std::numeric_limits<UINT64>::max)()) {
    throw IOException(_T("SecureChannel receive sequence is exhausted"));
  }

  UINT8 header[RECORD_HEADER_SIZE];
  readFully(header, sizeof(header));
  if (memcmp(header, RECORD_MAGIC, sizeof(RECORD_MAGIC)) != 0) {
    throw IOException(_T("Invalid encrypted record marker"));
  }

  UINT32 ciphertextLength = loadUInt32(header + 4);
  UINT64 sequence = loadUInt64(header + 8);
  if (ciphertextLength == 0 || ciphertextLength > MAX_PLAINTEXT_SIZE) {
    throw IOException(_T("Invalid encrypted record length"));
  }
  if (sequence != m_receiveSequence) {
    throw IOException(_T("Invalid encrypted record sequence"));
  }

  std::vector<UINT8> ciphertext(ciphertextLength);
  UINT8 tag[AUTH_TAG_SIZE];
  readFully(&ciphertext.front(), ciphertext.size());
  readFully(tag, sizeof(tag));

  try {
    m_receiveCipher->decrypt(&ciphertext.front(),
                             ciphertext.size(),
                             header,
                             sizeof(header),
                             sequence,
                             tag,
                             &m_plaintext);
  } catch (...) {
    SecureZeroMemory(tag, sizeof(tag));
    SecureZeroMemory(&ciphertext.front(), ciphertext.size());
    throw;
  }

  SecureZeroMemory(tag, sizeof(tag));
  SecureZeroMemory(&ciphertext.front(), ciphertext.size());
  m_plaintextPosition = 0;
  ++m_receiveSequence;
}

void SecureChannel::readFully(void *buffer, size_t length)
{
  UINT8 *destination = static_cast<UINT8 *>(buffer);
  size_t totalRead = 0;
  while (totalRead < length) {
    size_t bytesRead = m_channel->read(destination + totalRead,
                                       length - totalRead);
    if (bytesRead == 0) {
      throw IOException(_T("Connection closed inside an encrypted record"));
    }
    totalRead += bytesRead;
  }
}

void SecureChannel::writeFully(const void *buffer, size_t length)
{
  const UINT8 *source = static_cast<const UINT8 *>(buffer);
  size_t totalWritten = 0;
  while (totalWritten < length) {
    size_t bytesWritten = m_channel->write(source + totalWritten,
                                           length - totalWritten);
    if (bytesWritten == 0) {
      throw IOException(_T("Connection closed while writing an encrypted record"));
    }
    totalWritten += bytesWritten;
  }
}
