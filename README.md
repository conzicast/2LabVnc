# 2LabVnc

> **Solo Windows:** 2LabVnc funziona esclusivamente su Microsoft Windows,
> a partire da **Windows 7**. Non sono previste versioni Linux o macOS.

2LabVnc è un fork indipendente, distribuito con licenza GPLv2, derivato dal
codice di **TightVNC 2.x per Windows**. Il progetto mantiene le funzioni di
Server e Viewer di TightVNC e aggiunge un trasporto cifrato obbligatorio,
senza fallback verso sessioni RFB in chiaro.

2LabVnc non è un prodotto ufficiale TightVNC e non è affiliato a GlavSoft LLC.
I riferimenti a TightVNC descrivono esclusivamente l'origine del codice.

## Cosa aggiunge 2LabVnc

- tunnel RFB Tight proprietario e obbligatorio `CNSG/AESGCM01`;
- cifratura di tutto il traffico con AES-256-GCM;
- scambio effimero ECDH P-256;
- autenticazione della password con PBKDF2-HMAC-SHA-256;
- autenticazione reciproca del transcript e conferma protetta di attivazione;
- chiavi e nonce separati nelle due direzioni;
- protezione DPAPI delle credenziali memorizzate dal Server;
- installer selettivo per Server, Viewer o entrambi;
- regola Windows Firewall limitata alla feature Server;
- tray icon e collegamenti completi nel menu Start.

I dettagli crittografici e le istruzioni operative sono in
[docs/ENCRYPTION.md](docs/ENCRYPTION.md). L'installazione è descritta in
[docs/INSTALLATION.md](docs/INSTALLATION.md).

## Requisiti

- esclusivamente Windows 7 o versione successiva;
- architettura x86 oppure x64;
- accesso amministrativo per installare il Server, registrare il servizio e
  creare la regola firewall;
- Viewer e Server 2LabVnc: i client TightVNC originali non supportano il
  tunnel cifrato richiesto.

## Uso rapido

1. Installare la feature **2LabVnc Server** sul computer da controllare.
2. Impostare una password di cifratura dedicata di almeno 16 caratteri.
3. Lasciare aperta la porta TCP configurata, predefinita `5900`.
4. Installare **2LabVnc Viewer** sul computer operatore.
5. Connettersi all'indirizzo del Server e inserire la stessa password di
   cifratura.
6. Se sul Server è attivo `Require VNC authentication`, inserire anche la
   password VNC tradizionale.

La password di cifratura e la password VNC sono credenziali distinte. È
possibile disabilitare l'autenticazione VNC tradizionale e usare soltanto la
password di cifratura; in tal caso si rinuncia alla distinzione basata sulla
password VNC di sola visualizzazione.

## Build

La soluzione principale è `tightvnc2017.sln`. La build verificata usa:

- Visual Studio 2022 Build Tools;
- toolset MSVC `v143`;
- Windows 10 SDK, mantenendo `_WIN32_WINNT=0x0601`;
- WiX Toolset 3.14.1 per gli MSI x86 e x64.

Esempio x64:

```powershell
msbuild .\tightvnc2017.sln /m /t:Build `
  /p:Configuration=Release /p:Platform=x64 `
  /p:PlatformToolset=v143 /p:WindowsTargetPlatformVersion=10.0
```

## Licenza e attribuzione

2LabVnc è distribuito secondo la GNU General Public License v2. Il codice
originario TightVNC conserva le proprie intestazioni e attribuzioni. Vedere
[LICENSE](LICENSE) e [NOTICE.md](NOTICE.md).

Sito 2Lab: [www.2lab.it](https://www.2lab.it/)

