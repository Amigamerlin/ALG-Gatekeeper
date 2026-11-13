# ALG Gatekeeper

[![Build](../../actions/workflows/build.yml/badge.svg)](../../actions/workflows/build.yml)

**Un "fail2ban" per Windows.** ALG Gatekeeper legge il registro eventi di Windows, riconosce i tentativi di accesso
a forza bruta (Desktop remoto, SMB, SQL Server, SSH, VPN, Exchange, RD Web, MariaDB) e banna gli indirizzi IP
degli attaccanti nel Windows Firewall. Preconfigurato: si installa e funziona.

È un'evoluzione di [EvlWatcher](https://github.com/devnulli/EvlWatcher) di Michael Schönbauer (progetto non più mantenuto),
aggiornata, corretta e resa più robusta.

## Requisiti

- Windows Server 2012 R2 / 2016 / 2019 / 2022 / 2025 oppure Windows 10 / 11 (64 bit)
- .NET Framework 4.8 (già presente su tutti i sistemi aggiornati)

## Installazione

1. Scarica `ALGGatekeeper-x.y.z-setup.exe` dalla pagina **Releases** (o dagli *Artifacts* della build).
2. Avvialo come amministratore. Installazione silenziosa: `ALGGatekeeper-x.y.z-setup.exe /S`.

L'installer:
- registra il servizio Windows **ALGGatekeeper** (avvio automatico, riavvio automatico in caso di errore);
- negli aggiornamenti **conserva** la tua configurazione (whitelist, ban permanenti, impostazioni delle regole) e la unisce alle nuove regole;
- se trova **EvlWatcher**, lo rimuove e ne importa le impostazioni.

## Come funziona

Ogni 30 secondi il servizio legge i registri eventi. Se un IP sbaglia l'accesso troppe volte (predefinito: 5 volte in 2 minuti)
viene bannato per 1 ora. Dopo 3 ban temporanei il ban diventa **permanente**.
Tutti i valori si cambiano per ogni regola dalla console, scheda **Rules**.

I ban sono applicati tramite le regole firewall *"ALG Gatekeeper"*, *"ALG Gatekeeper #2"*, ... (1000 indirizzi per regola).
Ban e conteggi vengono salvati in `state.xml`: un riavvio non libera gli attaccanti.

## Protezione contro l'auto-ban

- **IP fidati automatici**: chi accede *con successo* via Desktop remoto o SSH diventa fidato per 30 giorni e non viene bannato.
- **Whitelist**: indirizzi singoli, reti CIDR (`93.40.0.0/16`, `2001:db8::/32`) o caratteri jolly (`192.168.*`).
  Le reti private (10/8, 172.16/12, 192.168/16) sono in whitelist di default.
- **Modalità simulazione** (*Global Settings*): registra chi verrebbe bannato senza toccare il firewall.
- **Uscita di emergenza**: fermare il servizio rimuove subito tutte le regole di blocco:
  ```
  sc stop ALGGatekeeper
  ```

## La console

`ALG Gatekeeper Console` (menu Start) mostra gli IP bannati/fidati, la whitelist, il log in tempo reale,
le impostazioni globali, le regole modificabili e un tester per le regex. Richiede i diritti di amministratore.

## Riga di comando

```
ALGGatekeeper.exe /console                      esegue il servizio in una finestra (fermare prima il servizio)
ALGGatekeeper.exe /validateconfig [file]        controlla config.xml
ALGGatekeeper.exe /migrateconfig <old> [new]    importa le impostazioni da un vecchio config.xml
ALGGatekeeper.exe /removefirewallrules [/legacy] rimuove le regole firewall (di EvlWatcher con /legacy)
ALGGatekeeper.exe /version
```

## Regole personalizzate

Le regole sono in `config.xml` (cartella di installazione), documentate nel file stesso.
L'IP viene estratto dal gruppo `(?<ip>...)` della regex o, se manca, dal primo gruppo.
Una regola `Type="Trust"` rende fidati gli IP che trova invece di bannarli.

## Compilare

```
dotnet build Source/ALGGatekeeper.sln -c Release
dotnet test  Source/ALGGatekeeper.Tests/ALGGatekeeper.Tests.csproj -c Release
makensis /DVERSION=1.0.0 Installer/ALGGatekeeper.nsi   (dopo aver copiato i file in Installer/payload)
```

Su GitHub tutto questo lo fa automaticamente il workflow [`.github/workflows/build.yml`](.github/workflows/build.yml):
ogni push produce il setup negli *Artifacts*; un tag `v1.2.3` crea anche la *Release*.

## Struttura

| Cartella | Contenuto |
|---|---|
| `Source/ALGGatekeeper` | il servizio (`ALGGatekeeper.exe`) e `config.xml` |
| `Source/ALGGatekeeper.Contracts` | interfaccia servizio ↔ console e funzioni condivise (IP, whitelist) |
| `Source/ALGGatekeeperConsole` | la console di gestione (WPF) |
| `Source/ALGGatekeeper.Tests` | test unitari |
| `Source/ALGGatekeeper.Tests.Integration` | test sul vero Windows Firewall (richiedono amministratore) |
| `Installer` | script NSIS del setup |

## Licenza

MIT – vedi [LICENSE](LICENSE). Basato su EvlWatcher © 2019-2024 Michael Schönbauer.
