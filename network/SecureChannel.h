// Copyright (C) 2026.
//
// Secure transport decorator for RFB channels. The class starts in pass-through
// mode and can be activated after protocol negotiation. Once active, it frames
// all traffic as authenticated AES-256-GCM records.

#ifndef _SECURE_CHANNEL_H_
#define _SECURE_CHANNEL_H_

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <vector>

#include "io-lib/Channel.h"
#include "util/inttypes.h"

class AesGcmState;

class SecureChannel : public Channel
{
public:
  static const size_t KEY_SIZE = 32;
  static const size_t NONCE_PREFIX_SIZE = 4;

  SecureChannel(Channel *channel);
  virtual ~SecureChannel();

  /**
   * Enables encryption for all subsequent reads and writes.
   *
   * Directional keys and nonce prefixes must be derived independently by the
   * handshake. A channel cannot return to pass-through mode or be re-keyed.
   */
  void activate(const UINT8 sendKey[KEY_SIZE],
                const UINT8 receiveKey[KEY_SIZE],
                const UINT8 sendNoncePrefix[NONCE_PREFIX_SIZE],
                const UINT8 receiveNoncePrefix[NONCE_PREFIX_SIZE]);

  bool isActive() const;

  virtual size_t read(void *buffer, size_t length) throw(IOException);
  virtual size_t write(const void *buffer, size_t length) throw(IOException);
  virtual size_t available();
  virtual void close() throw(Exception);

private:
  SecureChannel(const SecureChannel &);
  SecureChannel &operator=(const SecureChannel &);

  void readNextRecord();
  void readFully(void *buffer, size_t length);
  void writeFully(const void *buffer, size_t length);

  Channel *m_channel;
  AesGcmState *m_sendCipher;
  AesGcmState *m_receiveCipher;
  bool m_active;
  UINT64 m_sendSequence;
  UINT64 m_receiveSequence;
  std::vector<UINT8> m_plaintext;
  size_t m_plaintextPosition;
};

#endif // _SECURE_CHANNEL_H_
