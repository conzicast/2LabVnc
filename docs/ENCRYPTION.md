# Cifratura di 2LabVnc

> 2LabVnc e il suo trasporto cifrato sono disponibili esclusivamente su
> Windows, a partire da Windows 7.

## Obiettivo

Il protocollo RFB utilizzato da TightVNC 2.x non cifra nativamente tutto il
traffico della sessione. 2LabVnc inserisce un canale autenticato nella fase
Tight tunneling già prevista dal protocollo e rifiuta qualsiasi downgrade a
una connessione non cifrata.

Server e Viewer devono essere entrambi 2LabVnc. Un Viewer TightVNC originale
non riconosce il tunnel richiesto; un Viewer 2LabVnc rifiuta un Server che non
lo offre.

## Algoritmi e parametri

| Funzione | Implementazione |
| --- | --- |
| Cifratura traffico | AES-256-GCM tramite Windows CNG |
| Record | massimo 64 KiB di plaintext |
| Tag autenticazione | 16 byte per record |
| Scambio chiavi | ECDH effimero su curva P-256 |
| Password | PBKDF2-HMAC-SHA-256 |
| Iterazioni predefinite | 200.000 |
| Salt | casuale, 16 byte |
| Transcript | SHA-256 e HMAC-SHA-256 |
| Chiavi direzionali | due chiavi AES distinte, espanse con etichette HMAC |
| Nonce | prefissi distinti e contatori di sequenza a 64 bit |
| Capability tunnel | codice `0x434E5347`, vendor `CNSG`, firma `AESGCM01` |

Ogni record autentica anche il proprio header. Alterazioni del ciphertext,
sequenze inattese, record troncati e tag non validi interrompono la sessione.
L'overhead è di 32 byte per record: header autenticato e tag GCM.

## Handshake

1. Il Server annuncia esclusivamente il security type Tight e la capability
   `CNSG/AESGCM01`.
2. Il Server invia salt, numero di iterazioni, chiave pubblica ECDH effimera e
   materiale casuale.
3. Il Viewer deriva il verificatore PBKDF2 dalla password inserita, genera una
   propria coppia ECDH effimera e calcola il segreto condiviso.
4. Entrambe le parti autenticando il transcript con HMAC dimostrano di
   conoscere la password corretta.
5. Dal segreto dell'handshake vengono derivate separatamente le chiavi e i
   prefissi nonce client→server e server→client.
6. Una prova di attivazione autenticata definisce il confine esatto dopo il
   quale tutto il flusso RFB passa in AES-256-GCM.

Il Server non offre un percorso alternativo in chiaro.

## Configurare il Server

1. Aprire **2LabVnc Server - Tray and Settings** dal menu Start oppure fare
   clic sull'icona nella tray.
2. Nella pagina delle connessioni selezionare **Set...** accanto a
   `Encryption password`.
3. Inserire due volte una password dedicata lunga da 16 a 128 caratteri.
   Sono ammessi caratteri Unicode; Server e Viewer li codificano in UTF-8.
4. Applicare la configurazione.
5. Verificare che `Accept incoming connections` sia attivo e che la porta TCP
   configurata sia raggiungibile.

La configurazione post-installazione richiede la password di cifratura. Se il
prompt viene annullato, le connessioni RFB vengono disabilitate finché la
password non viene configurata.

## Connettere il Viewer

1. Avviare **2LabVnc Viewer**.
2. Inserire host e porta del Server.
3. Inserire la password nella finestra **2LabVnc Encryption Password**.
4. Se `Require VNC authentication` è abilitato sul Server, inserire anche la
   password VNC tradizionale nella finestra successiva.

L'errore `Encryption password is not configured on the server` indica che il
Server non ha ancora una password di cifratura. L'errore relativo alla
capability AES-GCM indica invece che si sta contattando un Server non
compatibile o una versione precedente del fork.

## Protezione della password

Il Server non salva la password in chiaro. Memorizza salt, iterazioni e
verificatore PBKDF2 all'interno di un blob protetto con Windows DPAPI in
machine scope e con interfaccia utente disabilitata. Il Viewer conserva la
password soltanto in memoria per la connessione corrente e la cancella dopo
l'attivazione del canale.

Il verificatore e un transcript di rete consentono comunque tentativi offline
sulla password. Usare quindi una password lunga, casuale, dedicata a 2LabVnc
e mai riutilizzata per account personali o aziendali.

## Password di cifratura e password VNC

Con la configurazione predefinita vengono richieste due password:

1. password di cifratura 2LabVnc, che autentica e protegge il tunnel;
2. password VNC tradizionale, che mantiene il modello accesso completo/sola
   visualizzazione ereditato da TightVNC.

Disabilitando `Require VNC authentication` rimane soltanto la password di
cifratura. Tutti gli utenti che la conoscono ottengono però il livello di
accesso configurato globalmente dal Server.

## Limiti operativi

- Gli eseguibili non sono firmati digitalmente finché non viene applicato un
  certificato code-signing del distributore.
- La compatibilità minima dichiarata è Windows 7; è raccomandato collaudare
  ogni release su una VM Windows 7 pulita oltre ai test automatici.
- La cifratura protegge il traffico tra Viewer e Server, non un endpoint già
  compromesso né la sicurezza fisica delle macchine.

