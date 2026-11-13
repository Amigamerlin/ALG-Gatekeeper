# Changelog

## 1.0.0 – 2026-11

Prima versione di **ALG Gatekeeper**, basata su EvlWatcher 2.1.62.

### Nuove funzioni
- **IP fidati**: chi accede con successo (Desktop remoto tipo 10/7, SSH) non viene bannato per 30 giorni.
- **Modalità simulazione**: registra i ban senza toccare il firewall.
- **Impostazioni delle regole dalla console** (attiva, durata ban, finestra, tentativi, ban permanente), applicate subito.
- **Whitelist con reti CIDR** (IPv4 e IPv6) oltre ai caratteri jolly.
- **Stato persistente**: ban temporanei, IP fidati e conteggi sopravvivono a riavvii e aggiornamenti.
- **Migrazione automatica** della configurazione negli aggiornamenti e da EvlWatcher.
- Riga di comando: `/console`, `/validateconfig`, `/migrateconfig`, `/removefirewallrules`, `/version`.
- Più di 1000 IP bannati: suddivisi automaticamente su più regole firewall.
- Supporto IPv6 nelle regole 4625, SQL Server, SSH, MariaDB, RD Web.
- Regola SQL Server estesa a tutti i login falliti (18456), MariaDB a tutti gli utenti.
- Build, test e setup automatici con GitHub Actions; setup NSIS senza plugin esterni.

### Sicurezza e affidabilità
- Le regex delle regole leggono l'IP scritto dal server e non uno nascosto nel nome utente: un attaccante non può far bannare un IP a sua scelta (EvlWatcher era vulnerabile per SSH, MariaDB e SQL Server).
- Tutti gli orari in UTC: il cambio dell'ora legale non falsa più finestre e conteggi.
- Gli eventi che hanno già causato un ban non vengono contati di nuovo; gli "strike" scadono dopo 30 giorni senza nuovi ban.
- Regole firewall: errori diversi da "regola non trovata" non creano duplicati; la connessione COM si ricrea dopo un errore; regole numerate cancellate a mano non lasciano blocchi orfani; azione "Blocca" e direzione "In ingresso" vengono sempre reimposte.
- Se config.xml non è scrivibile i ban vengono comunque applicati al firewall.
- L'interfaccia di gestione si apre solo dopo il caricamento della configurazione.
- Setup: negli aggiornamenti la cartella non si può cambiare; se il servizio non si ferma il setup si interrompe senza toccare nulla.
- `SaveGlobalConfig` era accessibile **senza** diritti di amministratore: corretto, ogni operazione verifica l'amministratore.
- Una regola non può mai essere attivata con l'elenco indirizzi vuoto ("blocca tutto"); prima si disattiva, poi si svuota.
- Regex con timeout di 2 s contro log costruiti per bloccare il servizio (ReDoS).
- `config.xml` salvato in modo atomico; DTD ed entità esterne disabilitate.
- Una regola errata viene saltata, le altre continuano a proteggere; valori fuori limite vengono corretti.
- Il setup non sovrascrive più `config.xml` (prima si perdevano whitelist e ban permanenti) e legge la cartella giusta negli aggiornamenti.
- Riavvio automatico del servizio in caso di errore.

### Correzioni
- Le regole `OnlyNew` perdevano eventi (veniva considerato "nuovo" solo il più recente).
- Gli eventi di regole con più registri venivano contati separatamente per registro.
- Il flag `Active` delle regole era sempre falso nella console.
- Il log del ban permanente mostrava il conteggio invece dell'IP.
- `ConsoleBacklog` di `config.xml` veniva ignorato.
- Indirizzi IPv4-mapped (`::ffff:1.2.3.4`) e IPv6 con scope (`%12`) non normalizzati; stringhe come `1.2` accettate come IP.
- Rilascio della risorsa COM del firewall con condizione invertita.
- Booster troppo generici (es. "4625" trovato anche in altri eventi): ora si usa l'ID evento esatto.
- La console creava una nuova connessione al servizio ogni secondo senza chiuderla.

### Prestazioni e memoria
- Gli eventi vengono filtrati dai booster già in lettura: in memoria resta solo l'XML degli eventi utili.
- Ogni evento viene convertito in XML una sola volta, anche se resta nella finestra per più cicli.
- I messaggi di debug (che contengono interi eventi) vengono generati solo se il livello di log lo richiede.
- La console scarica solo le nuove righe di log; il firewall viene aggiornato solo quando la lista cambia.
- Limite di sicurezza di 50.000 eventi letti per registro e ciclo.

### Tecnico
- .NET Framework 4.8 (compatibile da Windows Server 2012 R2), progetti SDK, una sola soluzione.
- API firewall tramite late binding COM (nessun import della type library).
- Codice obsoleto rimosso; 105 test unitari e test di integrazione sul firewall.
- Revisione di sicurezza indipendente del codice; tutti i punti segnalati sono stati corretti.
