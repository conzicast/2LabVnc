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
| Salt | 16 random bytes |
| Handshake transcript | SHA-256 and HMAC-SHA-256 |
| Directional keys | Separate AES keys derived using HMAC labels |
| Nonces | Distinct prefixes and 64-bit sequence counters |
| Tunnel capability | Code `0x434E5347`, vendor `CNSG`, signature `AESGCM01` |

Each record authenticates its header. Modified ciphertext, unexpected
sequence numbers, truncated records, and invalid tags terminate the
connection. The header and GCM tag add 32 bytes per record.

## Handshake

1. The Server offers only the Tight security type and the `CNSG/AESGCM01`
   tunnel capability.
2. The Server sends the salt, iteration count, ephemeral ECDH public key, and
   random data.
3. The Viewer derives the PBKDF2 verifier from the entered password,
   generates an ephemeral ECDH key pair, and computes the shared secret.
4. Both endpoints authenticate the handshake transcript with HMAC.
5. The handshake derives separate keys and nonce prefixes for the
   Viewer-to-Server and Server-to-Viewer directions.
6. An authenticated activation proof marks the point after which the entire
   RFB stream uses AES-256-GCM.

## Configure the Server

1. Open **2LabVnc Server - Tray and Settings** from the Start menu or click the
   Server icon in the notification area. If the Server runs as a service, use
   **2LabVnc Service - Tray and Settings**.
2. On the connections page, select **Set...** next to **Encryption password**.
3. Enter a dedicated password of 16 to 128 characters twice. Unicode is
   supported and is encoded as UTF-8 on both ends.
4. Apply the settings.
5. Make sure **Accept incoming connections** is enabled and the configured
   TCP port is reachable.

Server setup prompts for the encryption password after installation.
Cancelling that prompt disables incoming RFB connections until the password
is configured. Enable incoming connections in the Server settings when ready.

## Connect from the Viewer

1. Launch **2LabVnc Viewer**.
2. Enter the Server host and port.
3. Enter the password in the **2LabVnc Encryption Password** dialog.
4. If **Require VNC authentication** is enabled on the Server, enter the
   traditional VNC password in the next dialog.

If you see `Encryption password is not configured on the server`, set the
encryption password in the Server settings. If the Viewer reports that the
required AES-GCM capability is missing, check the host and port and make sure
you are connecting to a compatible 2LabVnc Server.

## Password storage and access

The Server stores the salt, iteration count, and PBKDF2 verifier in a
Windows DPAPI blob protected at machine scope. The Viewer keeps the password
in memory for the current connection and clears it after channel activation.

Use a long, randomly generated password dedicated to 2LabVnc. A captured
handshake or an exposed verifier can support offline password guessing.

With traditional VNC authentication enabled, the encryption password
authenticates the tunnel and the VNC password determines full-control or
view-only access. With traditional VNC authentication disabled, users who
know the encryption password receive the access level configured globally
on the Server.

## Operational limits

- The 1.0.0 installers and executables are unsigned.
- Windows 7 is the configured minimum. Release 1.0.0 has yet to be tested on
  a clean Windows 7 VM.
- Encryption protects traffic between the Viewer and Server. Endpoint and
  physical security remain separate concerns.
