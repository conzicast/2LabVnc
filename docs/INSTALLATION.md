# Installazione di 2LabVnc

> **Piattaforma supportata: esclusivamente Windows 7 o successivo.**

## Scelta dei componenti

L'installer permette di selezionare:

- **2LabVnc Server**: servizio Windows, tray icon, impostazioni, regola
  firewall e strumenti del menu Start;
- **2LabVnc Viewer**: applicazione client e associazione opzionale dei file
  `.vnc`;
- entrambi i componenti.

## Server

1. Eseguire l'MSI adatto all'architettura del sistema come amministratore.
2. Selezionare la feature **2LabVnc Server**.
3. Lasciare attiva la registrazione come servizio, salvo esigenze specifiche.
4. Scegliere la porta RFB, predefinita `5900`.
5. Impostare la password di cifratura quando richiesta.
6. Configurare la password VNC tradizionale oppure disabilitare esplicitamente
   `Require VNC authentication`.

La feature Server crea una sola regola Windows Firewall TCP sulla porta RFB
configurata. La feature Viewer non apre porte firewall.

Il servizio si chiama `2LabVncServer` ed è visualizzato come
`2LabVnc Server`. La configurazione è salvata sotto
`HKLM\Software\2Lab\2LabVnc\Server`.

## Tray icon e menu Start

Il clic sull'icona Server nella tray apre le impostazioni. Il menu Start
contiene collegamenti per:

- avvio Server in modalità applicazione;
- tray e impostazioni;
- configurazione offline;
- registrazione, avvio, arresto e rimozione del servizio.

## Viewer

1. Selezionare la feature **2LabVnc Viewer**.
2. Avviare `2LabVnc Viewer` dal menu Start.
3. Collegarsi all'indirizzo del Server.
4. Inserire la password di cifratura e, se richiesta, quella VNC.

## Coesistenza con TightVNC

2LabVnc usa nomi servizio, directory, chiavi di registro, mutex e pipe propri.
Può quindi essere installato senza presentarsi come aggiornamento ufficiale di
TightVNC. Due Server non possono tuttavia ascoltare contemporaneamente sulla
stessa porta TCP: assegnare porte diverse oppure arrestare il Server che non
deve essere utilizzato.

