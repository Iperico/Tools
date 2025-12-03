-- m00_core_01_forensics_schema_init.sql
--
-- Schema iniziale DB forense (SQLite) per il progetto DB FORENSIC.
-- Contiene le tabelle master, le tabelle eventi principali e le tabelle
-- di acquisizione per Android ADB e (in bozza) Windows logs.
--
-- Eseguire con qualcosa tipo:
--   cd C:\SAFENET\DB
--   sqlite3 forensic.db ".read C:/SAFENET/Tools/m00_core_01_forensics_schema_init.sql"
--
-- Nota: tutte le CREATE usano IF NOT EXISTS per poter essere rilanciate in sicurezza.

PRAGMA foreign_keys = ON;

-- ============================================================================
-- 1) MASTER TABLES
-- ============================================================================

-- 1.1 DEVICE_MASTER
-- Anagrafica di tutti i device: PC, telefoni, router, repeater, TV, Raspberry, ecc.
CREATE TABLE IF NOT EXISTS DEVICE_MASTER (
    device_id        INTEGER PRIMARY KEY,
    device_label     VARCHAR(80)  NOT NULL, -- es. PC_ALE_OLD, S20_ALESSIA
    hostname         VARCHAR(120),
    device_type      VARCHAR(40),          -- PC, ANDROID, ROUTER, REPEATER, TV, RASPBERRY, ...
    os_name          VARCHAR(80),
    os_version       VARCHAR(80),
    serial_or_imei   VARCHAR(80),
    mac_lan          VARCHAR(32),
    mac_wifi         VARCHAR(32),
    ip_lan_tipico    VARCHAR(64),
    owner_declared   VARCHAR(120),         -- chi dice di possedere il device
    notes            TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_device_label
    ON DEVICE_MASTER (device_label);


-- 1.2 ACCOUNT_MASTER
-- Catalogo degli account (Gmail, Drive, utenti Windows, VPN, ecc.).
CREATE TABLE IF NOT EXISTS ACCOUNT_MASTER (
    account_id       INTEGER PRIMARY KEY,
    account_label    VARCHAR(80)  NOT NULL,  -- es. GMAIL_ALESSIA
    account_type     VARCHAR(40),            -- GMAIL, DRIVE, WINDOWS, VPN, ...
    username_email   VARCHAR(160) NOT NULL,
    owner_declared   VARCHAR(120),
    main_device_id   INTEGER,                -- device "principale" se esiste
    notes            TEXT,
    FOREIGN KEY (main_device_id) REFERENCES DEVICE_MASTER(device_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_account_label
    ON ACCOUNT_MASTER (account_label);


-- 1.3 INTERFACE_MASTER
-- "Middleware" logico tra device e rete: interfacce LAN/Wi-Fi/VPN con MAC/IP tipici.
CREATE TABLE IF NOT EXISTS INTERFACE_MASTER (
    interface_id      INTEGER PRIMARY KEY,
    device_id         INTEGER NOT NULL,      -- a quale device appartiene
    interface_label   VARCHAR(80) NOT NULL,  -- es. SPARTACUS_LAN, S20_WIFI_5G
    interface_type    VARCHAR(40),           -- WIFI, ETHERNET, VIRTUAL, VPN, ...
    ssid              VARCHAR(80),           -- se Wi-Fi
    bssid             VARCHAR(32),           -- MAC dell'AP, se nota
    mac_address       VARCHAR(32),
    ip_lan_tipico     VARCHAR(64),
    gateway_device_id INTEGER,               -- router / repeater / firewall
    notes             TEXT,
    FOREIGN KEY (device_id)         REFERENCES DEVICE_MASTER(device_id),
    FOREIGN KEY (gateway_device_id) REFERENCES DEVICE_MASTER(device_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_interface_device_label
    ON INTERFACE_MASTER (device_id, interface_label);


-- ============================================================================
-- 2) ACQUISITIONS TABLES
-- ============================================================================

-- 2.1 ANDROID_ACQUISTIONS
-- Meta delle acquisizioni ADB da android_log_dump_0.2 (e simili).
CREATE TABLE IF NOT EXISTS ANDROID_ACQUISITIONS (
    acquisition_id       INTEGER PRIMARY KEY,
    device_id            INTEGER NOT NULL,      -- FK -> DEVICE_MASTER(device_id)
    run_id               VARCHAR(32) NOT NULL,  -- es. 20251129_031934
    script_name          VARCHAR(80),          -- es. 'android_log_dump'
    script_version       VARCHAR(20),          -- es. '0.2'
    source_run_dir       TEXT,                 -- path sorgente android_logs\...
    target_run_base      TEXT,                 -- path base in DataSetGlobal\...
    acquisition_time_utc TIMESTAMP,            -- se disponibile (nome run o meta)
    validation_status    VARCHAR(20),          -- NULL / OK / WARN / ERROR
    notes                TEXT,
    FOREIGN KEY (device_id) REFERENCES DEVICE_MASTER(device_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_android_acq_device_run_script
    ON ANDROID_ACQUISITIONS (device_id, run_id, script_name, script_version);


-- 2.2 WINDOWS_ACQUISITIONS (bozza, per futura M02)
CREATE TABLE IF NOT EXISTS WINDOWS_ACQUISITIONS (
    acquisition_id       INTEGER PRIMARY KEY,
    device_id            INTEGER NOT NULL,      -- FK -> DEVICE_MASTER(device_id)
    run_id               VARCHAR(32) NOT NULL,  -- es. 20251129_120000
    log_type             VARCHAR(40),           -- Security, System, Application, PowerShell, ...
    tool_name            VARCHAR(80),           -- es. 'wevutil', 'Get-WinEvent', script custom
    tool_version         VARCHAR(20),
    source_path          TEXT,                  -- path agli .evtx / .csv originali
    target_run_base      TEXT,                  -- path base in DataSetGlobal\windows_logs\...
    acquisition_time_utc TIMESTAMP,
    validation_status    VARCHAR(20),           -- NULL / OK / WARN / ERROR
    notes                TEXT,
    FOREIGN KEY (device_id) REFERENCES DEVICE_MASTER(device_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_win_acq_device_run_type
    ON WINDOWS_ACQUISITIONS (device_id, run_id, log_type, tool_name);


-- ============================================================================
-- 3) EVENT TABLES
-- ============================================================================

-- 3.1 EVENTI_CLOUD (Drive / Gmail / altri log Google)
CREATE TABLE IF NOT EXISTS EVENTI_CLOUD (
    event_id             INTEGER PRIMARY KEY,
    timestamp_utc        TIMESTAMP NOT NULL,
    account_id           INTEGER NOT NULL,      -- FK -> ACCOUNT_MASTER
    device_id            INTEGER,              -- se dal log capiamo il device
    ip_remoto            VARCHAR(64),
    prodotto             VARCHAR(40),          -- GMAIL, DRIVE, DOCS, ...
    tipo_evento          VARCHAR(80),          -- es. drive_share_link, gmail_login
    target_id            VARCHAR(256),         -- id file, label, cartella...
    target_descr         TEXT,                 -- nome file, oggetto mail, ecc.
    raw_ref              VARCHAR(512),         -- path nel JSON sorgente
    sospetto_flag        BOOLEAN DEFAULT 0,
    motivazione_sospetto TEXT,
    FOREIGN KEY (account_id) REFERENCES ACCOUNT_MASTER(account_id),
    FOREIGN KEY (device_id)  REFERENCES DEVICE_MASTER(device_id)
);

CREATE INDEX IF NOT EXISTS idx_cloud_ts
    ON EVENTI_CLOUD (timestamp_utc);

CREATE INDEX IF NOT EXISTS idx_cloud_account_ts
    ON EVENTI_CLOUD (account_id, timestamp_utc);


-- 3.2 EVENTI_PC (log Windows, PowerShell, AMSI, ecc.)
CREATE TABLE IF NOT EXISTS EVENTI_PC (
    event_id             INTEGER PRIMARY KEY,
    timestamp_utc        TIMESTAMP NOT NULL,
    device_id            INTEGER NOT NULL,     -- FK -> DEVICE_MASTER
    source_log           VARCHAR(80),          -- Security, System, PowerShell, ...
    event_code           INTEGER,              -- 4624, 4625, 4720, 7045, ...
    account_id           INTEGER,              -- se mappabile a utente/account
    ip_remoto            VARCHAR(64),
    logon_type           INTEGER,              -- per eventi 4624/4625
    process_name         VARCHAR(260),
    command_line         TEXT,
    description          TEXT,
    sospetto_flag        BOOLEAN DEFAULT 0,
    motivazione_sospetto TEXT,
    FOREIGN KEY (device_id)  REFERENCES DEVICE_MASTER(device_id),
    FOREIGN KEY (account_id) REFERENCES ACCOUNT_MASTER(account_id)
);

CREATE INDEX IF NOT EXISTS idx_pc_ts
    ON EVENTI_PC (timestamp_utc);

CREATE INDEX IF NOT EXISTS idx_pc_device_ts
    ON EVENTI_PC (device_id, timestamp_utc);

CREATE INDEX IF NOT EXISTS idx_pc_account_ts
    ON EVENTI_PC (account_id, timestamp_utc);


-- 3.3 EVENTI_RETE (pcap, sniff, WAN monitor, router)
CREATE TABLE IF NOT EXISTS EVENTI_RETE (
    net_event_id         INTEGER PRIMARY KEY,
    timestamp_start_utc  TIMESTAMP NOT NULL,
    timestamp_end_utc    TIMESTAMP,
    device_id            INTEGER,           -- chi sta generando il traffico
    interface_id         INTEGER,           -- quale interfaccia (se nota)
    captured_by_device_id INTEGER,          -- sonda/middleware che osserva (es. Raspberry)
    ip_locale            VARCHAR(64),
    porta_locale         INTEGER,
    ip_remoto            VARCHAR(64),
    porta_remota         INTEGER,
    protocollo           VARCHAR(16),       -- TCP, UDP, ICMP...
    service_guess        VARCHAR(40),       -- https, rdp, dns, telegram, ...
    asn_remoto           INTEGER,
    org_remota           VARCHAR(160),
    categoria_ip         VARCHAR(40),       -- big_provider, vpn_lavoro, vps_sconosciuto, ...
    bytes_sent           BIGINT,
    bytes_received       BIGINT,
    sospetto_flag        BOOLEAN DEFAULT 0,
    motivazione_sospetto TEXT,
    FOREIGN KEY (device_id)             REFERENCES DEVICE_MASTER(device_id),
    FOREIGN KEY (interface_id)          REFERENCES INTERFACE_MASTER(interface_id),
    FOREIGN KEY (captured_by_device_id) REFERENCES DEVICE_MASTER(device_id)
);

CREATE INDEX IF NOT EXISTS idx_net_ts
    ON EVENTI_RETE (timestamp_start_utc);

CREATE INDEX IF NOT EXISTS idx_net_device_ts
    ON EVENTI_RETE (device_id, timestamp_start_utc);

CREATE INDEX IF NOT EXISTS idx_net_ip_remoto_ts
    ON EVENTI_RETE (ip_remoto, timestamp_start_utc);


-- 3.4 EVENTI_ANDROID (ADB logs, Takeout, My Activity, ecc.)
CREATE TABLE IF NOT EXISTS EVENTI_ANDROID (
    android_event_id     INTEGER PRIMARY KEY,
    timestamp_utc        TIMESTAMP NOT NULL,   -- timestamp evento (UTC)
    device_id            INTEGER NOT NULL,     -- FK -> DEVICE_MASTER
    account_id           INTEGER,              -- FK -> ACCOUNT_MASTER (se noto)
    product              VARCHAR(80),          -- es. 'Android', 'YouTube', 'Chrome'
    app                  VARCHAR(80),          -- package / nome app
    title                TEXT,                 -- titolo evento
    title_url            TEXT,                 -- URL associato (se esiste)
    source_file          VARCHAR(260),         -- file sorgente (logcat_xxx, dumpsys_yyy, ...)
    ip_remoto            VARCHAR(64),          -- IP remoto se estratto
    extra_details        TEXT,                 -- JSON o testo con info extra
    sospetto_flag        BOOLEAN DEFAULT 0,
    motivazione_sospetto TEXT,
    FOREIGN KEY (device_id)  REFERENCES DEVICE_MASTER(device_id),
    FOREIGN KEY (account_id) REFERENCES ACCOUNT_MASTER(account_id)
);

CREATE INDEX IF NOT EXISTS idx_android_ts
    ON EVENTI_ANDROID (timestamp_utc);

CREATE INDEX IF NOT EXISTS idx_android_device_ts
    ON EVENTI_ANDROID (device_id, timestamp_utc);

CREATE INDEX IF NOT EXISTS idx_android_account_ts
    ON EVENTI_ANDROID (account_id, timestamp_utc);


-- ============================================================================
-- 4) TIMELINE UNIFICATA
-- ============================================================================

CREATE TABLE IF NOT EXISTS TIMELINE_MASTER (
    timeline_id       INTEGER PRIMARY KEY,
    timestamp_utc     TIMESTAMP NOT NULL,
    source_table      VARCHAR(40) NOT NULL,   -- EVENTI_PC / EVENTI_ANDROID / EVENTI_CLOUD / EVENTI_RETE / ...
    source_event_id   INTEGER NOT NULL,       -- PK nella tabella sorgente
    device_id         INTEGER,                -- FK -> DEVICE_MASTER
    account_id        INTEGER,                -- FK -> ACCOUNT_MASTER
    ip_remoto         VARCHAR(64),
    evento_breve      VARCHAR(255),          -- descrizione breve per analisi
    autore_probabile  VARCHAR(40),           -- UTENTE_TU, UTENTE_ALTRI, TERZO_SCONOSCIUTO, SISTEMA, INCERTO
    confidence        INTEGER,               -- 1..5
    sospetto_flag     BOOLEAN DEFAULT 0,
    categoria_sospetto VARCHAR(80),          -- ACCESSO_NON_AUTORIZZATO, ESFILTRAZIONE, ...
    note              TEXT,
    FOREIGN KEY (device_id)  REFERENCES DEVICE_MASTER(device_id),
    FOREIGN KEY (account_id) REFERENCES ACCOUNT_MASTER(account_id)
);

CREATE INDEX IF NOT EXISTS idx_timeline_ts
    ON TIMELINE_MASTER (timestamp_utc);

CREATE INDEX IF NOT EXISTS idx_timeline_device_ts
    ON TIMELINE_MASTER (device_id, timestamp_utc);

CREATE INDEX IF NOT EXISTS idx_timeline_account_ts
    ON TIMELINE_MASTER (account_id, timestamp_utc);

