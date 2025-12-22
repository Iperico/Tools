# SAFENET → MySQL (locale) — Tutorial + Checklist operativa

Questa guida “chiude il cerchio” per passare dalla pipeline SQLite al backend **MySQL 8** in locale, mantenendo la logica a milestone (Bootstrap → M01 Android → M02 Windows).

Riferimenti al progetto:
- La pipeline a milestone è descritta in `README.md` e `00_TUTORIAL_DB_FORENSIC.md` (init → extract → validate → load). 
- La UI (viewer) espone i parametri MySQL nel modal *Settings* e li salva in `forensic_config.json`. 

---

## 0) Obiettivo pratico (cosa ottieni)
1. Un database `forensic` in MySQL con layer “core” (DEVICE_MASTER, ACCOUNT_MASTER, SCHEMA_VERSION).
2. Tabelle milestone in MySQL (Android + Windows).
3. Una strategia anti-duplicati (perché hai log “prima e dopo” e vuoi concentrarti 09–12/2025).
4. Una check-list ripetibile, così non diventi un film di Nolan ogni volta che riparti.

---

## 1) Blocco attuale: `ERROR 1045 Access denied for user 'root'@'localhost'`

Questo errore significa che:
- password errata **oppure**
- account `root@localhost` non è abilitato come pensi (plugin auth diverso, utente differente, ecc.)

### 1A. Verifiche “soft” (2 minuti)
- Verifica che il servizio MySQL sia *Running* (Services → **MySQL80**).
- Prova con l’host esplicito:
  - `mysql -u root -p -h 127.0.0.1`
- Se in passato usavi Workbench: prova il login da lì (ti dice subito se è solo la password).

### 1B. Fix “hard” (reset credenziali) — percorso più affidabile su Windows
Hai 2 strade, scegli quella che ti fa dormire:

**Opzione 1 (consigliata): MySQL Installer / Workbench reset**
- Se hai MySQL Installer (quello “ufficiale”), usa la funzione *Reconfigure* / *Reset Root Password*.
- È la via più pulita: niente avvii in modalità insicura.

**Opzione 2 (manuale): avvio temporaneo senza grant tables**
1. Stop servizio: `net stop MySQL80`
2. Avvia temporaneamente:
   - `mysqld --skip-grant-tables --skip-networking`
3. In un altro terminale:
   - `mysql -u root`
4. Esegui:
   - `FLUSH PRIVILEGES;`
   - (Poi imposti una password nuova per `root@localhost` o crei un nuovo admin locale)
5. Stop mysqld e riavvia servizio normale: `net start MySQL80`

> Nota: questa opzione è potente come una motosega. Falla **offline** (skip-networking già aiuta) e solo il tempo minimo indispensabile.

---

## 2) Bootstrap DB (Stage 0)

### 2A. Esegui bootstrap
Script: `mysql_forensic_init.sql` (crea DB + user `safenet_admin` + master tables + SCHEMA_VERSION).

Esempio:
```powershell
cd C:\Program Files\MySQL\MySQL Server 8.0\bin
.\mysql.exe -u root -p < C:\SAFENET\Tools\mysql_forensic_init.sql
```

Output atteso (concettuale):
- DB `forensic` esiste
- Tabelle: `DEVICE_MASTER`, `ACCOUNT_MASTER`, `SCHEMA_VERSION`
- `SCHEMA_VERSION` contiene `core-bootstrap`

### 2B. Login con service account
```powershell
.\mysql.exe -u safenet_admin -p forensic
```

Verifica:
```sql
SHOW TABLES;
SELECT * FROM SCHEMA_VERSION;
```

---

## 3) Milestone tables (M01 + M02) in MySQL

### 3A. Applica M01 (Android)
Userai la versione MySQL dell’init:
- `m01_android_adb_01_init.mysql.sql`

Esecuzione:
```powershell
.\mysql.exe -u safenet_admin -p forensic < C:\SAFENET\Tools\m01_android_adb_01_init.mysql.sql
```

### 3B. Applica M02 (Windows)
Userai:
- `m02_windows_logs_01_init.mysql.sql`

Esecuzione:
```powershell
.\mysql.exe -u safenet_admin -p forensic < C:\SAFENET\Tools\m02_windows_logs_01_init.mysql.sql
```

---

## 4) Config “UI-first”: `forensic_config.json`

La UI salva i campi MySQL in `forensic_config.json` (host/port/user/password/db). 
È già allineata come concetto: *Settings → Save → persistenza → refresh*.

Campi attesi (da ReadUI.md):
- workspace_folder (default `C:\SAFENET`)
- mysql_host / mysql_port (default `127.0.0.1:3306`)
- mysql_user / mysql_password / mysql_database  (esempio default: `forensic/forensic/forensic`) 

Consiglio fermo: **usa safenet_admin** (non root) per gli script. Root è per bootstrap/DDL, non per ingest.

---

## 5) Python: driver MySQL

Installa driver:
```bash
pip install mysql-connector-python
```

Snippet (test connessione):
```python
import mysql.connector
cnx = mysql.connector.connect(
    host="127.0.0.1",
    port=3306,
    user="safenet_admin",
    password="ChangeMe!2025",
    database="forensic",
)
cur = cnx.cursor()
cur.execute("SELECT COUNT(*) FROM DEVICE_MASTER")
print(cur.fetchone())
cnx.close()
```

---

## 6) Duplicazioni: strategia pratica (log “prima/dopo” + focus 09–12/2025)

Hai due problemi distinti:
1. **Duplicati tecnici**: stesso evento ingestito due volte (stesso file, stesso run, re-run script).
2. **Duplicati semantici**: stesso evento presente in due esportazioni diverse (overlap temporale o re-export).

### 6A. Anti-duplicati sulle ACQUISITIONS
Già previsto: chiave unica (device_id, run_id, log_type, tool_name) per Windows e (device_id, run_id, script_name, script_version) per Android.

### 6B. Anti-duplicati sugli eventi (EVENTI_PC)
Nello script MySQL M02 ho aggiunto un campo opzionale `event_fingerprint` + UNIQUE:
- `UNIQUE(device_id, source_log, event_code, timestamp_utc, event_fingerprint)`

Idea:
- calcoli SHA-256 su un “payload” stabile: es. `"{source_log}|{event_code}|{timestamp}|{description}"` 
- inserisci con `INSERT IGNORE` o `INSERT ... ON DUPLICATE KEY UPDATE`

Questo ti permette di:
- re-ingestare senza panico
- fare prove (dry-run) e iterazioni senza rovinare i dati

---

## 7) Checklist finale (stampabile)

### Stage 0 — DB
- [ ] MySQL80 running
- [ ] Login admin (root o equivalente) funziona
- [ ] Eseguito `mysql_forensic_init.sql`
- [ ] Login `safenet_admin` OK
- [ ] `DEVICE_MASTER`, `ACCOUNT_MASTER`, `SCHEMA_VERSION` presenti

### Stage 1 — Schema milestone
- [ ] Eseguito `m01_android_adb_01_init.mysql.sql`
- [ ] Eseguito `m02_windows_logs_01_init.mysql.sql`

### Stage 2 — Config & ingest
- [ ] `forensic_config.json` valorizzato (host/port/user/db)
- [ ] Driver Python MySQL installato
- [ ] Test connessione Python OK
- [ ] Strategy dedup abilitata (fingerprint / INSERT IGNORE)

### Stage 3 — Analisi 09–12/2025
- [ ] Query filtrate per range date (WHERE timestamp_utc BETWEEN '2025-09-01' AND '2025-12-31 23:59:59')
- [ ] Query per device (SPARTACUS vs VAGABONDO)
- [ ] Report “prima/dopo” con conteggi (per source_log, event_code, day)

---

## Nota “umano-legale” (1 riga, ma pesante)
Questa pipeline serve a trasformare sensazioni in **evidenze verificabili** (chi, quando, cosa). Poi la strategia (HR/Legal/forensics esterna) la scegli con più controllo e meno ansia.

