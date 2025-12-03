# DB FORENSIC – TUTORIAL & ROADMAP (SQLite, per milestone)

Questo file descrive **come usare il progetto DB FORENSIC a milestone**, con
comandi concreti (per ora usando **SQLite** e **script Python locali**).

L’idea: non rifare ogni volta il setup da zero, ma avere una sequenza chiara per
ogni sorgente di log (Android ADB, Windows log, Takeout, Drive, Gmail, …).

---

## 0. Prerequisiti generali

### 0.1. Strumenti

- **Python 3.x** disponibile in `PATH` (es. `python` o `python3`)
- **SQLite CLI** (`sqlite3`) installata e disponibile in `PATH`
- Struttura directory tipo:

  ```text
  C:\SAFENET\
    DataSetGlobal\          <-- destinazione normalizzata (SAFENET)
    DB\                      <-- dove tenere il DB forense .sqlite
    Tools\                   <-- script Python / SQL del progetto
  ```

Puoi ovviamente adattare i path, ma in questo tutorial useremo:

- Database: `C:\SAFENET\DB\forensic.db`
- Script SQL/Python: `C:\SAFENET\Tools\...`

### 0.2. Convezioni file / milestone

Per ogni “sorgente” di dati ci saranno almeno:

- `mXX_<source>_01_init.sql` → inizializzazione tabelle per quel tipo (ACQUISITIONS, EVENTI_*)
- `mXX_<source>_02_extract_to_safenet.py` → da dump grezzi → SAFENET `DataSetGlobal\...`
- `mXX_<source>_02b_validate_safenet.py` → controllo di integrità
- `mXX_<source>_03_load_to_EVENTI_*.py` → da SAFENET → tabelle EVENTI_* nel DB

Dove `XX` è il numero milestone, e `<source>` qualcosa tipo `android_adb`, `windows_logs`, ecc.

---

## 1. Creazione / apertura DB SQLite

Se non hai ancora il DB forense:

```bash
cd C:\SAFENET\DB
sqlite3 forensic.db
```

Dentro la shell di sqlite puoi verificare che è vuoto:

```sql
.tables
```

(Non deve restituire nulla o solo le tabelle di sistema).

Per uscire:

```sql
.quit
```

---

## 2. Milestone M01 – Android ADB logs

**Scopo**: acquisizioni da `android_log_dump_0.2` → SAFENET → pronti per EVENTI_ANDROID.

### 2.1. Inizializzazione tabelle Android (init SQL)

Assumiamo di aver copiato:

- `m01_android_adb_01_init.sql` in `C:\SAFENET\Tools\`

Lanciare:

```bash
cd C:\SAFENET\DB
sqlite3 forensic.db ".read C:/SAFENET/Tools/m01_android_adb_01_init.sql"
```

Oppure entrare nella shell:

```bash
cd C:\SAFENET\DB
sqlite3 forensic.db
```

e poi:

```sql
.read C:/SAFENET/Tools/m01_android_adb_01_init.sql
.tables
```

Dovresti vedere comparire almeno:

- `ANDROID_ACQUISITIONS`
- `EVENTI_ANDROID`

> Nota: si assume che `DEVICE_MASTER` e `ACCOUNT_MASTER` siano già stati creati in altre fasi del progetto.

### 2.2. Preparazione directory sorgente Android

La sorgente dei dump ADB la immaginiamo così:

```text
D:\Evidence\ANDROID_Mobile\android_logs\
  samsung_SM-S921B_RZCX60536TD_20251129_031934\
  samsung_SM-G980F_RF8N31XTXAD_20251129_035052\
  samsung_SM-A600FN_5200870afec93535_20251129_040926\
    device_info_*.txt
    logcat_main_*.txt
    logcat_events_*.txt
    logcat_radio_*.txt
    logcat_crash_*.txt
    getprop_*.txt
    dmesg_*.txt
    dumpsys_*_*.txt
    packages_*_*.txt
    ...
```

### 2.3. Normalizzazione in SAFENET (estrazione)

Assumiamo di avere uno script tipo:

- `m01_android_adb_02_extract_to_safenet.py` (derivato da `android_logs_to_safenet_auto.py`)

e che sia in `C:\SAFENET\Tools\`.

Esempio di esecuzione:

```bash
cd C:\SAFENET\Tools

python m01_android_adb_02_extract_to_safenet.py ^
    --source "D:/Evidence/ANDROID_Mobile/android_logs" ^
    --target "C:/SAFENET/DataSetGlobal/android_adb_logs" ^
    --db "C:/SAFENET/DB/forensic.db"
```

Lo script deve:

1. Leggere le cartelle `samsung_*_<run_id>` dalla sorgente.
2. Mappare il pattern sul `device_logical` (es. `ANDR_IO_S24`, `ANDR_ALE_S20`, `ANDR_ALE_A6`).
3. Creare la struttura:

   ```text
   C:\SAFENET\DataSetGlobal\android_adb_logs\<device_logical>\android_log_dump_0.2\<run_id>\...
   ```

4. Copiare i file in `RAW_ALL`, `META`, `CORE_SYSTEM`, `CONNECTIVITY`, `APPS_PACKAGES`.
5. Scrivere/aggiornare `META/acquisition_meta.json`.
6. Inserire una riga in `ANDROID_ACQUISITIONS` per ogni run (usando il DB indicato con `--db`).

### 2.4. Validazione integrità (Android)

Assumiamo di avere:

- `m01_android_adb_02b_validate_safenet.py` (derivato da `validation_android.py`)

Esempio uso:

```bash
cd C:\SAFENET\Tools

python m01_android_adb_02b_validate_safenet.py ^
    --source "D:/Evidence/ANDROID_Mobile/android_logs" ^
    --target "C:/SAFENET/DataSetGlobal/android_adb_logs" ^
    --db "C:/SAFENET/DB/forensic.db"
```

Lo script dovrebbe:

- confrontare i file sorgente con quelli in `RAW_ALL` (nome, dimensione, opzionale hash)
- verificare che i file con prefissi noti siano presenti anche nelle categorie (`CORE_SYSTEM`, ecc.)
- aggiornare eventualmente `ANDROID_ACQUISITIONS` con lo stato di validazione
- uscire con exit code 0 se tutto ok, >0 se c’è qualche problema

### 2.5. Popolamento EVENTI_ANDROID (fase successiva)

Script previsto (non ancora implementato):  
`m01_android_adb_03_load_to_EVENTI_ANDROID.py`

Esempio di uso previsto:

```bash
cd C:\SAFENET\Tools

python m01_android_adb_03_load_to_EVENTI_ANDROID.py ^
    --target "C:/SAFENET/DataSetGlobal/android_adb_logs" ^
    --db "C:/SAFENET/DB/forensic.db"
```

Questo script leggerà i file in `CORE_SYSTEM`, `CONNECTIVITY`, `APPS_PACKAGES` e `META`,
riconoscerà gli eventi di interesse (pattern su logcat, dumpsys, ecc.) e li tradurrà in
righe di `EVENTI_ANDROID` con:

- `timestamp_utc`
- `device_id`
- `account_id` (se mappabile)
- `product`, `app`, `title`, `title_url`
- `source_file`, `ip_remoto`, `extra_details`
- `sospetto_flag`, `motivazione_sospetto`

---

## 3. Milestone M02 – Windows logs (bozza)

> ⚠️ Questa sezione è un **placeholder**: serve solo per dare la forma modulare.
> Il dettaglio verrà definito dopo aver chiuso bene M01.

### 3.1. Init Windows

File previsto:

- `m02_windows_logs_01_init.sql`

Comandi tipici:

```bash
cd C:\SAFENET\DB
sqlite3 forensic.db ".read C:/SAFENET/Tools/m02_windows_logs_01_init.sql"
```

Dovrebbe creare:

- `WINDOWS_ACQUISITIONS`
- assicurare l’esistenza/struttura di `EVENTI_PC`

### 3.2. Estrattore Windows → SAFENET

File previsto:

- `m02_windows_logs_02_extract_to_safenet.py`

Esempio uso:

```bash
cd C:\SAFENET\Tools

python m02_windows_logs_02_extract_to_safenet.py ^
    --source "D:/Evidence/WINDOWS_Logs" ^
    --target "C:/SAFENET/DataSetGlobal/windows_logs" ^
    --db "C:/SAFENET/DB/forensic.db"
```

### 3.3. Validazione & load

Analoghi a M01:

- `m02_windows_logs_02b_validate_safenet.py`
- `m02_windows_logs_03_load_to_EVENTI_PC.py`

---

## 4. Milestone future (placeholder comandi)

Analogamente verranno aggiunte:

- **M03 – Takeout / My Activity**
- **M04 – Drive activity**
- **M05 – Gmail activity**
- **M06 – TIMELINE_MASTER**

Ognuna con i suoi file:

- `m0X_<source>_01_init.sql`
- `m0X_<source>_02_extract_to_safenet.py`
- `m0X_<source>_02b_validate_safenet.py`
- `m0X_<source>_03_load_to_EVENTI_*.py`

e comandi d’esempio in questo stesso `00_TUTORIAL_DB_FORENSIC.md`.

---

## 5. Strategia di lavoro consigliata

1. **Chiudere M01 Android ADB** end-to-end:
   - init SQL eseguito
   - estrazione funzionante per S24 / S20 / A6
   - validazione pulita
   - (idealmente) prima versione di `*_load_to_EVENTI_ANDROID.py` anche se minimale

2. Solo dopo, passare a **M02 Windows logs** con lo stesso schema mentale.

3. Evitare di mescolare i passi delle milestone: ogni sorgente deve avere
   la sua mini-pipeline completa e documentata qui, così non ti ritrovi
   con script zombie difficili da manutenere.
