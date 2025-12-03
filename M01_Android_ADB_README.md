# M01 – Android ADB logs → SAFENET → EVENTI_ANDROID

Questo README descrive la **pipeline Android ADB** all’interno del progetto DB FORENSIC.

Obiettivo della milestone **M01**:  
partire dai dump grezzi presi con `android_log_dump_0.2` tramite `adb`, portarli in una struttura
forense stabile sotto `DataSetGlobal`, e infine usarli per popolare la tabella `EVENTI_ANDROID`.

---

## 1. Scope della milestone M01

Questa milestone copre **solo**:

- Acquisizioni ADB da telefoni Android tramite `android_log_dump_0.2`
- Normalizzazione in `DataSetGlobal\android_adb_logs\...`
- Tracciamento delle acquisizioni nella tabella `ANDROID_ACQUISITIONS`
- Preparazione della tabella `EVENTI_ANDROID` per ospitare eventi futuri

Non copre ancora il parser che traduce i log in eventi forensi (`*_load_to_EVENTI_ANDROID.py`),
ma prepara tutto il terreno perché quel passo sia semplice e ripetibile.

---

## 2. Struttura cartelle – sorgente e destinazione

### 2.1. Sorgente: dump ADB grezzi

I dump originali stanno (esempio):

```text
<BASE>\ANDROID_Mobilendroid_logs  samsung_SM-S921B_RZCX60536TD_20251129_031934  samsung_SM-G980F_RF8N31XTXAD_20251129_035052  samsung_SM-A600FN_5200870afec93535_20251129_040926    device_info_<ts>.txt
    logcat_main_<ts>.txt
    logcat_events_<ts>.txt
    logcat_radio_<ts>.txt
    logcat_crash_<ts>.txt
    getprop_<ts>.txt
    dmesg_<ts>.txt
    dumpsys_*_<ts>.txt
    packages_*_<ts>.txt
    ps_full_<ts>.txt
    netstat_<ts>.txt
    ip_*_<ts>.txt
    df_<ts>.txt
    mounts_<ts>.txt
    settings_*_<ts>.txt
    report_summary_<readable_ts>.txt
    ...
```

Ogni cartella rappresenta **una run di acquisizione** di `android_log_dump_0.2`.

Il nome della cartella codifica:

- brand/model/serial, es. `samsung_SM-S921B_RZCX60536TD`
- timestamp run, es. `20251129_031934`

### 2.2. Destinazione: struttura normalizzata SAFENET

I dati vengono spostati/normalizzati in:

```text
C:\SAFENET\DataSetGlobal\android_adb_logs\
  <device_logical>\
    android_log_dump_0.2\
      <run_id>\
        META\
        CORE_SYSTEM\
        CONNECTIVITY\
        APPS_PACKAGES\
        RAW_ALL\
```

Dove:

- `<device_logical>` è un nome stabile collegato al `DEVICE_MASTER.device_label`
  (es. `ANDR_IO_S24`, `ANDR_ALE_S20`, `ANDR_ALE_A6`).
- `android_log_dump_0.2` identifica **lo strumento di acquisizione**.
- `<run_id>` di solito coincide con il timestamp `YYYYMMDD_HHMMSS`.

Significato delle sottocartelle:

- `RAW_ALL` → copia 1:1 **di tutti i file originali** della run (cassaforte integrale).
- `META` → file descrittivi (`device_info_*.txt`, `getprop_*.txt`, `report_summary_*`) +
  un file `acquisition_meta.json` con info aggiuntive (device, serial, run_id, ecc.).
- `CORE_SYSTEM` → log principali di sistema: `logcat_main`, `logcat_events`,
  `logcat_radio`, `logcat_crash`, `dmesg`, `settings_*`, `df`, `mounts`, ecc.
- `CONNECTIVITY` → `netstat`, `ip_*`, `dumpsys_connectivity`, `dumpsys_wifi`, ecc.
- `APPS_PACKAGES` → `dumpsys_package`, `packages_*`, `ps_full`, ecc.

---

## 3. Tabelle DB coinvolte in M01

### 3.1. DEVICE_MASTER (pre-esistente)

Gli smartphone Android devono essere presenti in `DEVICE_MASTER`, ad es.:

- `ANDR_IO_S24` (S24 tuo)
- `ANDR_ALE_S20` (S20 di Ale)
- `ANDR_ALE_A6` (A6 di Ale)

Questi record **non sono creati** da questa init, ma sono un prerequisito.
Gli script di estrazione guardano a questi label per posizionare i dati in SAFENET
ed i parser futuri li useranno per risalire al `device_id` numerico.

### 3.2. ANDROID_ACQUISITIONS

Nuova tabella che registra **ogni run di acquisizione ADB**:

- quale device è stato acquisito
- dove si trovano i dati originali e quelli normalizzati
- quando è avvenuta l’acquisizione
- che script/versione è stato usato

Vedi la sezione **4. Android init SQL** per il DDL completo.

### 3.3. EVENTI_ANDROID

Tabella dove finiranno gli **eventi logici Android** (da ADB, Takeout, ecc.).

Per questa milestone:

- viene creata se non esiste.
- non viene ancora popolata.
- funge da destinazione per uno script successivo
  (`m01_android_adb_03_probe_load_to_EVENTI_ANDROID.py`).

---

## 4. Android init SQL

Il file `m01_android_adb_01_init.sql` contiene:

1. Creazione di `ANDROID_ACQUISITIONS`
2. Creazione (se non esiste) di `EVENTI_ANDROID`
3. Indici di base per performance

Puoi eseguirlo una volta sul database principale per inizializzare la parte Android.

Contenuto completo del file è in `m01_android_adb_01_init.sql` a fianco di questo README.

---

## 5. Workflow M01 (end-to-end)

1. **Init DB (una volta)**  
   Esegui:

   ```sql
   -- dentro il tuo DB forense
   .read m01_android_adb_01_init.sql
   ```

2. **Acquisizione ADB**  
   Lanci `android_log_dump_0.2` sui device Android (S24, S20, A6).
   I dump finiscono sotto `ANDROID_Mobile\android_logs\...`.

3. **Normalizzazione in SAFENET**  
   Esegui lo script (nome indicativo):

   ```bash
   python m01_android_adb_02_extract_to_safenet.py --source ANDROID_Mobile/android_logs --target C:\SAFENET\DataSetGlobal\android_adb_logs
   ```

   Lo script:
   - mappa le cartelle `samsung_*` sul device logico (`ANDR_IO_S24`, ecc.)
   - crea la struttura `<device_logical>\android_log_dump_0.2\<run_id>\...`
   - genera/aggiorna `META/acquisition_meta.json`
   - inserisce una riga in `ANDROID_ACQUISITIONS` per ogni run

4. **Validazione**  
   Lanci lo script di validazione, ad es.:

   ```bash
   python m01_android_adb_02b_validate_safenet.py --source ANDROID_Mobile/android_logs --target C:\SAFENET\DataSetGlobal\android_adb_logs
   ```

   Se la validazione passa (nessun file perso, dimensioni/hash coerenti), la run è considerata **forensic-ready**.

5. **Popolamento EVENTI_ANDROID (fase successiva)**  
   In una milestone successiva si aggiungerà:

   ```bash
   python m01_android_adb_03_probe_load_to_EVENTI_ANDROID.py --target C:\SAFENET\DataSetGlobal\android_adb_logs
   ```

   che leggerà `CORE_SYSTEM`, `CONNECTIVITY`, `APPS_PACKAGES` e `META`,
   estrarrà gli eventi di interesse e li inserirà nella tabella `EVENTI_ANDROID`.

---

## 6. Cosa resta da fare dopo M01

Dopo che M01 è stabile, la roadmap prevede:

- **M02 – Windows log**: stessa logica (ACQUISITIONS, SAFENET, EVENTI_PC)
- **M03 – Takeout / My Activity**: eventi aggiuntivi in `EVENTI_ANDROID` / `EVENTI_CLOUD`
- **M04 – Drive activity**
- **M05 – Gmail activity**
- **M06 – TIMELINE_MASTER** con attribuzione `autore_probabile` e `confidence`.

La milestone **M01** chiude quando:

- `ANDROID_ACQUISITIONS` è popolata per S24, S20, A6
- i dump ADB sono tutti normalizzati e validati in SAFENET
- `EVENTI_ANDROID` è pronta e referenziata correttamente alle tabelle master.
