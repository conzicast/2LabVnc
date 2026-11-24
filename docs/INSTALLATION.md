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
5. When setup reports success, click **Finish**. In the Server password
   window that opens, set and confirm the full-control and view-only passwords.
   The two passwords must differ and each must contain at least 16 characters.
   The eye button below the password fields shows or hides both fields in
   the current dialog. Validation messages appear directly below the fields.
6. If setup skips the prompt, open Server settings and select **Set...** under
   **Full control and view only**. Apply the settings and enable incoming connections.
7. After confirming the passwords, use **Copy fingerprint** to copy
   the Server fingerprint. It is also available under **Fingerprint...** in
   Server settings. Share it through a trusted channel.

When the setup wizard registers the Server as a Windows service, it saves
the passwords in **Service Mode**. To retrieve its fingerprint from the
Start menu, open **2LabVnc Server (Service Mode)**, select
**2LabVnc Service - Offline Settings**, and click **Fingerprint...**.
**Application Mode** has its own passwords and fingerprint.

With the Windows Firewall option enabled, the installer creates one inbound
TCP rule for the Server's RFB port. Viewer-only installs add no firewall rules.

The internal service name is `2LabVncServer` and its display name is
`2LabVnc Server`. Service settings are stored under
`HKLM\Software\2Lab\2LabVnc\Server`.

## Notification area and Start menu

When you click **Finish**, interactive setup opens the Server notification
area icon on the Windows desktop running the wizard, including a Remote
Desktop session. This uses the same command as the Start menu shortcut.
The service also starts the icon for users already signed in, and the
icon starts at subsequent sign-ins. Windows may place it in the hidden icons area.
The tray retries registration if Windows Explorer is still starting.

Click the Server icon in the Windows notification area to set or change
the full-control and view-only passwords or edit other Server settings.
Windows prompts for administrator rights when configuring the service.
Closing the service settings dialog reloads the saved configuration.
The Start menu includes shortcuts to run the Server in application mode,
open tray controls and settings, edit offline configuration, and register,
start, stop, or remove the service.

## Install the Viewer

1. Select **2LabVnc Viewer** on the computer you will use to connect.
2. Launch **2LabVnc Viewer** from the Start menu.
3. Connect to the Server address and port.
4. On the first connection, compare the fingerprint displayed by the Viewer
   with the one provided by your administrator. Select **I verified the fingerprint**
   only if they match.
5. Enter one password for the access level you want. After secure authentication,
   the Viewer remembers the identity by host and port for direct connections.
   If it changes, compare the new fingerprint with the value from your
   administrator and select **I verified the new fingerprint** only if they
   match. Successful authentication saves the update. Reverse connections
   require confirmation each time.

## Upgrade from a version before 1.2.0

Arrange local access to the Server first. Update the Server and Viewer together,
set two fresh role passwords on the Server, and distribute its fingerprint.
Earlier versions use an incompatible protocol. See the [encryption guide](ENCRYPTION.md).

## Remove the Server

Uninstall **2LabVnc** from **Programs and Features**. The installer stops and
removes the `2LabVncServer` Windows service before deleting the Server files.
Setup asks the Server tray to exit and allows up to 15 seconds for it
to release the executable before Windows Installer checks for files in use.

During interactive Server removal, choose **No** to delete both role
passwords and the Server identity, or keep the default **Yes** to reuse
them after reinstalling. The choice covers Service Mode and Application
Mode for the Windows account running setup. Cleanup runs after a successful
uninstall. Upgrades and silent removals keep these credentials.

If Windows Installer reports that files are in use, cancel the uninstall.
From **2LabVnc Server (Service Mode)** in the Start menu, run
**Stop 2LabVnc Service** as an administrator and wait until the service has
stopped. Close the Server tray and any open 2LabVnc windows, then retry.
Stopping the service disconnects active Viewer sessions.

## Run alongside TightVNC

2LabVnc uses its own service name, directories, registry keys, mutexes, and
pipes, so it can be installed alongside TightVNC. If both servers run on
the same machine, assign them different TCP ports or stop the server you
are not using.
