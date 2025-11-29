INSERT INTO DEVICE_MASTER (
    device_id,
    device_label,
    hostname,
    device_type,
    os_name,
    os_version,
    serial_or_imei,
    mac_lan,
    mac_wifi,
    ip_lan_tipico,
    owner_declared,
    notes
) VALUES
-- Samsung S20 (Ale)
(201, 'Samsung_S20', NULL, 'ANDROID',
 'Android', NULL,
 'RF8N31XTXAD',      -- dal nome cartella originale samsung_SM-G980F_RF8N31XTXAD_...
 NULL, NULL, NULL,
 'Ale',
 'Samsung S20 di Ale, acquisito via android_log_dump_0.2'),

-- Samsung S24 (tuo)
(202, 'Samsung_S24', NULL, 'ANDROID',
 'Android', NULL,
 'RZCX60536TD',      -- dal nome cartella originale samsung_SM-S921B_RZCX60536TD_...
 NULL, NULL, NULL,
 'IO',
 'Samsung S24 (tuo), acquisito via android_log_dump_0.2'),

-- Samsung A6 (Ale)
(203, 'Samsung_SM-A600FN', NULL, 'ANDROID',
 'Android', NULL,
 '5200870afec93535', -- dal nome cartella originale samsung_SM-A600FN_5200870afec93535_...
 NULL, NULL, NULL,
 'Ale',
 'Samsung A6 di Ale, acquisito via android_log_dump_0.2');
