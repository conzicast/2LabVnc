# 2LabVnc encryption

> **Windows only. Requires Windows 7 or later.**

2LabVnc negotiates an authenticated encrypted channel during the Tight
tunneling phase of RFB. The encrypted channel protects all subsequent RFB
traffic. Both endpoints must run 2LabVnc. The Server requires the tunnel, and
the Viewer rejects servers that do not offer it. There is no plaintext fallback.

## Algorithms and parameters

| Function | Implementation |
| --- | --- |
| Traffic encryption | AES-256-GCM via Windows CNG |
| Record | Up to 64 KiB of plaintext |
| Authentication tag | 16 bytes per record |
| Key exchange | Ephemeral ECDH on P-256 |
| Password derivation | PBKDF2-HMAC-SHA-256 |
| Default iteration count | 200,000 |
| Salt | 16 random bytes generated when the password pair is set |
| Handshake transcript | SHA-256 and HMAC-SHA-256 |
| Directional keys | Separate AES keys derived using HMAC labels |
| Nonces | Distinct prefixes and 64-bit sequence counters |
| Server identity | ECDSA P-256 with a pinned SHA-256 fingerprint |
| Tunnel capability | Code `0x434E5347`, vendor `CNSG`, signature `AESGCM03` |

Each record authenticates its header. Modified ciphertext, unexpected
sequence numbers, truncated records, and invalid tags terminate the
connection. The header and GCM tag add 32 bytes per record.

## Handshake

1. The Server offers only the Tight security type and the `CNSG/AESGCM03`
   tunnel capability.
2. The Server sends a signed hello with the salt, iteration count, random
   data, ephemeral ECDH key, and public identity key.
3. The Viewer verifies the signature and checks the Server fingerprint against
   its saved value or asks the operator to confirm it. Only then does it ask
   for a password, derive the verifier, and compute the ephemeral ECDH secret.
4. Both endpoints authenticate the transcript with HMAC. The Server checks the
   Viewer proof against both verifiers and assigns the role from the unique match.
5. The handshake derives separate keys and nonce prefixes for the
   Viewer-to-Server and Server-to-Viewer directions.
6. An authenticated activation proof marks the point after which the entire
   RFB stream uses AES-256-GCM.

## Configure the Server

1. Open **2LabVnc Server - Tray and Settings** from the Start menu or click the
   Server icon in the notification area. If the Server runs as a service, use
   **2LabVnc Service - Tray and Settings**.
2. On the connections page, select **Set...** under **Full control and view only**.
3. Set and confirm each password. Use at least 16 characters per password and
   choose two different passwords. The eye button toggles visibility for both
   fields in the current dialog. Passwords support Unicode and use UTF-8 on
   both ends.
4. Apply the settings.
5. Open **Fingerprint...** and copy the Server's 64-character fingerprint.
   Share it with the Viewer user through a trusted channel.
6. Make sure **Accept incoming connections** is enabled and the configured
   TCP port is reachable.

Server setup can prompt for both passwords after installation. If you cancel
the initial setup, set the pair in Server settings and enable incoming connections.
The Server refuses sessions until a valid pair is configured.

## Connect from the Viewer

1. Launch **2LabVnc Viewer**.
2. Enter the Server host and port.
3. Compare the first-use fingerprint displayed by the Viewer with the one
   shown at Server setup or supplied through a trusted channel. If it matches,
   select **I verified the fingerprint**.
4. Enter the password for your role in the single **2LabVnc Password** prompt.
   After secure authentication, the Viewer remembers the fingerprint for
   the address and port of a direct connection. It blocks a changed identity
   before asking for the password. Reverse connections require a fresh comparison.
5. When the first remote image arrives, the Viewer briefly displays
   **Encryption enabled** with a green check mark. The notice lasts two seconds.

**Show encryption notice in Viewer** is enabled by default in Server settings.
Changing it affects only this notice on subsequent connections. Encryption
remains mandatory.

If the Server requests configuration of both passwords, set the pair in
Server settings. A missing AES-GCM capability can indicate a mismatched
Server or Viewer version. Update both endpoints when moving from any version
before 1.2.0 and set fresh passwords.

## Password storage and access

The Server stores the salt, iteration count, both PBKDF2 verifiers, and the
private identity key in a Windows DPAPI blob protected at machine scope.
Changing passwords preserves the existing identity. To rotate the identity,
clear both passwords, apply, then set and apply a fresh pair.
After verifying an intentional key change with the administrator, remove
the corresponding `ServerFingerprint.<host>.<port>` value from
`HKEY_CURRENT_USER\Software\2Lab\2LabVnc\Viewer\Settings` on the Viewer
and verify the new fingerprint at the next connection.
The Viewer keeps the password
in memory for the current connection and clears it after channel activation.

Use long, randomly generated passwords dedicated to 2LabVnc. Protect the
Server's stored credentials and share the fingerprint separately from the passwords.

Full-control sessions can use input, clipboard, and file transfer when Server
settings permit them. View-only sessions receive screen updates without input,
clipboard exchange, or file transfer.

## Operational limits

- The installers and executables are unsigned.
- Windows 7 is the configured minimum. Compatibility on a clean Windows 7 VM
  still needs verification.
- Encryption protects traffic between the Viewer and Server. Endpoint and
  physical security remain separate concerns.
