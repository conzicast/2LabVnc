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
| Tunnel capability | Code `0x434E5347`, vendor `CNSG`, signature `AESGCM02` |

Each record authenticates its header. Modified ciphertext, unexpected
sequence numbers, truncated records, and invalid tags terminate the
connection. The header and GCM tag add 32 bytes per record.

## Handshake

1. The Server offers only the Tight security type and the `CNSG/AESGCM02`
   tunnel capability.
2. The Server sends the salt, iteration count, ephemeral ECDH public key, and
   random data.
3. The Viewer derives the PBKDF2 verifier from the entered password,
   generates an ephemeral ECDH key pair, and computes the shared secret.
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
5. Make sure **Accept incoming connections** is enabled and the configured
   TCP port is reachable.

Server setup can prompt for both passwords after installation. If you cancel
the initial setup, set the pair in Server settings and enable incoming connections.
The Server refuses sessions until a valid pair is configured.

## Connect from the Viewer

1. Launch **2LabVnc Viewer**.
2. Enter the Server host and port.
3. Enter the password for your role in the single **2LabVnc Password** prompt.
4. When the first remote image arrives, the Viewer briefly displays
   **Encryption enabled** with a green check mark. The notice lasts two seconds.

**Show encryption notice in Viewer** is enabled by default in Server settings.
Changing it affects only this notice on subsequent connections. Encryption
remains mandatory.

If the Server requests configuration of both passwords, set the pair in
Server settings. A missing AES-GCM capability can indicate a mismatched
Server or Viewer version. Update both endpoints when moving from 1.0.x.

## Password storage and access

The Server stores the salt, iteration count, and both PBKDF2 verifiers in a
Windows DPAPI blob protected at machine scope. The Viewer keeps the password
in memory for the current connection and clears it after channel activation.

Use a long, randomly generated password dedicated to 2LabVnc. A captured
handshake or an exposed verifier can support offline password guessing.

Full-control sessions can use input, clipboard, and file transfer when Server
settings permit them. View-only sessions receive screen updates without input,
clipboard exchange, or file transfer.

## Operational limits

- The installers and executables are unsigned.
- Windows 7 is the configured minimum. Compatibility on a clean Windows 7 VM
  still needs verification.
- Encryption protects traffic between the Viewer and Server. Endpoint and
  physical security remain separate concerns.
