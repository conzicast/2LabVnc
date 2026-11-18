# 2LabVnc

> **Windows only. Minimum version: Windows 7.** Installers are available for x86
> and x64. Linux and macOS builds are unavailable.

2LabVnc is an independent GPLv2 fork of **TightVNC 2.x for Windows**, based on
TightVNC 2.8.90. It retains the Server and Viewer and adds mandatory,
authenticated AES-256-GCM encryption for the RFB session after the handshake.
2LabVnc is maintained by 2lab snc and is unaffiliated with GlavSoft LLC.

## No warranty and limitation of liability

2LabVnc is provided **"AS IS"**, without warranty of any kind, express or
implied, to the extent permitted by applicable law. Except where required by
applicable law or agreed in writing, the copyright holders and contributors
are not liable for damages arising from use of, or inability to use, the software.
See sections 11 and 12 of the [GNU GPLv2 license](LICENSE).

## Features

- Mandatory Tight RFB tunnel (`CNSG/AESGCM01`) with no plaintext fallback
- AES-256-GCM with separate keys and nonce sequences in each direction
- Ephemeral ECDH P-256 key exchange and PBKDF2-HMAC-SHA-256 password derivation
- Mutual handshake authentication and authenticated channel activation
- Windows DPAPI protection for credentials stored by the Server
- MSI installer with Server, Viewer, or both
- Windows Firewall option for the Server, plus a notification area icon and Start menu shortcuts

## Requirements

- Microsoft Windows 7 or later, x86 or x64
- Administrator rights to install the Server, register the service, and add the firewall rule
- 2LabVnc on both ends of the connection

Windows 7 is the configured minimum. Release 1.0.0 has yet to be tested on a
clean Windows 7 VM.

## Quick start

1. Download the MSI for your architecture from [GitHub Releases](https://github.com/conzicast/2LabVnc/releases).
2. Install **2LabVnc Server** on the computer you want to control.
3. Set a dedicated encryption password of 16 to 128 characters. Allow incoming
   connections on the configured TCP port, which defaults to `5900`.
4. Install **2LabVnc Viewer** on the computer you will use to connect.
5. Connect to the Server and enter the same encryption password. If
   `Require VNC authentication` is enabled, enter the traditional VNC password
   in the second prompt.

The encryption password and the traditional VNC password are separate
credentials. Turning off `Require VNC authentication` leaves a single
password prompt and removes the distinction between full-control and
view-only access based on the traditional VNC password.

See the [installation guide](docs/INSTALLATION.md) and
[encryption guide](docs/ENCRYPTION.md) for setup, troubleshooting, and
protocol details.

## Build

The main solution is `tightvnc2017.sln`. The verified build uses Visual Studio
2022 Build Tools, the MSVC `v143` toolset, and the Windows 10 SDK with
`_WIN32_WINNT=0x0601`. The x86 and x64 MSI packages use WiX Toolset 3.14.1.

Build the x64 configuration with PowerShell:

```powershell
msbuild .\tightvnc2017.sln /m /t:Build `
  /p:Configuration=Release /p:Platform=x64 `
  /p:PlatformToolset=v143 /p:WindowsTargetPlatformVersion=10.0
```

## License and attribution

2LabVnc is distributed under the GNU General Public License v2. The original
TightVNC copyright and attribution notices are retained.
See [LICENSE](LICENSE) and [NOTICE.md](NOTICE.md).

[2Lab website](https://www.2lab.it/)
