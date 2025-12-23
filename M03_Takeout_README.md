# M03 - Google Takeout -> SAFENET -> EVENTI_ANDROID

Pipeline Takeout per DB FORENSIC / SAFENET.

## Scope
- Copia Takeout in DataSetGlobal.
- Normalizzazione CSV con report.
- Validazione.
- Inserimento in EVENTI_ANDROID (loader SQLite legacy).

## Struttura SAFENET attesa

```text
C:\SAFENET\DataSetGlobal\takeout\
  <account_label>\
    takeout_<run_id>\
      RAW_ALL\
      REPORT\
      META\
        acquisition_meta.json
```

## DDL
- `m03_takeout_01_init.sql` (porting MySQL in progress).

## Script della milestone
- Runner: `m03_takeout_00_interactive_runner.py`
- Extract: `m03_takeout_02_extract_to_safenet.py`
- Validate: `m03_takeout_02b_validate_safenet.py`
- Load (probe): `m03_takeout_03_probe_load_to_EVENTI_ANDROID.py` (SQLite legacy)

## Procedura standard (M03)
1. Eseguire il DDL della milestone.
2. Extract:

```bash
python C:\SAFENET\Tools\m03_takeout_02_extract_to_safenet.py ^
  --source "C:\Users\...\Takeout" ^
  --target "C:\SAFENET\DataSetGlobal\takeout" ^
  --account-label "ACC_OMI_MAIN"
```

3. Validazione:

```bash
python C:\SAFENET\Tools\m03_takeout_02b_validate_safenet.py ^
  --dataset-root "C:\SAFENET\DataSetGlobal\takeout" ^
  --account-label "ACC_OMI_MAIN"
```

4. Load (probe, SQLite legacy):

```bash
python C:\SAFENET\Tools\m03_takeout_03_probe_load_to_EVENTI_ANDROID.py ^
  --dataset-root "C:\SAFENET\DataSetGlobal\takeout" ^
  --db "C:\SAFENET\DB\forensic.db" ^
  --account-label "ACC_OMI_MAIN" ^
  --source-type "PLAY_INSTALLS"
```

## Note
- Il loader M03 e' ancora SQLite. Per allinearsi allo standard MySQL va portato.
- `ACCOUNT_MASTER` deve contenere l'account_label usato nei dataset.
