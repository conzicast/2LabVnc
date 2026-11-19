# Installing 2LabVnc

> **Windows only. Requires Windows 7 or later.**

Download the MSI for your system architecture, x86 or x64, from
[GitHub Releases](https://github.com/conzicast/2LabVnc/releases).

## Choose components

- **2LabVnc Server** provides the Windows service, notification area icon,
  settings, Windows Firewall option, and Start menu tools.
- **2LabVnc Viewer** provides the client and an optional `.vnc` file association.
- Select both components if you need both functions on the same computer.

## Install the Server

1. Run the MSI as an administrator on the computer you want to control.
2. Select **2LabVnc Server**.
3. Keep the option to register the Server as a Windows service enabled if
   you want the Server to run as a service.
4. Note the default RFB port, TCP `5900`. You can change the port in Server
   settings and adjust the firewall rule to match.
5. Set and confirm the full-control and view-only passwords when prompted.
   The two passwords must differ and each must contain at least 16 characters.
   The eye button shows or hides both fields in the current dialog.
6. If setup skips the prompt, open Server settings and select **Set...** under
   **Full control and view only**. Apply the settings and enable incoming connections.
7. Open **Fingerprint...** in Server settings after applying the passwords.
   Copy the fingerprint and share it through a trusted channel.

With the Windows Firewall option enabled, the installer creates one inbound
TCP rule for the Server's RFB port. Viewer-only installs add no firewall rules.

The internal service name is `2LabVncServer` and its display name is
`2LabVnc Server`. Service settings are stored under
`HKLM\Software\2Lab\2LabVnc\Server`.

## Notification area and Start menu

Click the Server icon in the Windows notification area to open settings.
Windows prompts for administrator rights when configuring the service.
Closing the service settings dialog reloads the saved configuration.
The Start menu includes shortcuts to run the Server in application mode,
open tray controls and settings, edit offline configuration, and register,
start, stop, or remove the service.

## Install the Viewer

1. Select **2LabVnc Viewer** on the computer you will use to connect.
2. Launch **2LabVnc Viewer** from the Start menu.
3. Connect to the Server address and port.
4. Enter the fingerprint obtained from your administrator and one password
   for the access level you want. The Viewer remembers the fingerprint by
   host and port for direct connections. Enter it manually for a reverse connection.

## Upgrade from a version before 1.2.0

Arrange local access to the Server first. Update the Server and Viewer together,
set two fresh role passwords on the Server, and distribute its fingerprint.
Earlier versions use an incompatible protocol. See the [encryption guide](ENCRYPTION.md).

## Run alongside TightVNC

2LabVnc uses its own service name, directories, registry keys, mutexes, and
pipes, so it can be installed alongside TightVNC. If both servers run on
the same machine, assign them different TCP ports or stop the server you
are not using.
