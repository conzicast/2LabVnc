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
5. Set the encryption password when prompted.
6. Set the traditional VNC password or turn off `Require VNC authentication`.
   See the [encryption guide](ENCRYPTION.md) for how this affects access.

With the Windows Firewall option enabled, the installer creates one inbound
TCP rule for the Server's RFB port. Viewer-only installs add no firewall rules.

The internal service name is `2LabVncServer` and its display name is
`2LabVnc Server`. Service settings are stored under
`HKLM\Software\2Lab\2LabVnc\Server`.

## Notification area and Start menu

Click the Server icon in the Windows notification area to open settings.
The Start menu includes shortcuts to run the Server in application mode,
open tray controls and settings, edit offline configuration, and register,
start, stop, or remove the service.

## Install the Viewer

1. Select **2LabVnc Viewer** on the computer you will use to connect.
2. Launch **2LabVnc Viewer** from the Start menu.
3. Connect to the Server address and port.
4. Enter the encryption password and, if prompted, the traditional VNC password.

## Run alongside TightVNC

2LabVnc uses its own service name, directories, registry keys, mutexes, and
pipes, so it can be installed alongside TightVNC. If both servers run on
the same machine, assign them different TCP ports or stop the server you
are not using.
