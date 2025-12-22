

PS C:\SAFENET\ForEnrollStuff> Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Windows Error Reporting'} -MaxEvents 50 |
>> Select TimeCreated, Id, Message

TimeCreated           Id Message
-----------           -- -------
21/12/2025 22:48:05 1001 Bucket errato INVALID_REQUEST, tipo 0...
21/12/2025 22:48:04 1001 Bucket errato INVALID_REQUEST, tipo 0...
21/12/2025 22:48:03 1001 Bucket errato , tipo 0...
21/12/2025 22:48:02 1001 Bucket errato , tipo 0...
21/12/2025 15:52:48 1001 Bucket errato 1460668297071276994, tipo 4...
21/12/2025 10:12:33 1001 Bucket errato INVALID_REQUEST, tipo 0...
21/12/2025 10:12:31 1001 Bucket errato , tipo 0...
21/12/2025 08:33:34 1001 Bucket errato INVALID_REQUEST, tipo 0...
21/12/2025 08:33:33 1001 Bucket errato INVALID_REQUEST, tipo 0...
21/12/2025 08:21:03 1001 Bucket errato , tipo 0...
21/12/2025 08:21:03 1001 Bucket errato , tipo 0...
21/12/2025 08:20:13 1001 Bucket errato , tipo 0...
21/12/2025 08:20:13 1001 Bucket errato , tipo 0...
21/12/2025 08:20:13 1001 Bucket errato , tipo 0...
21/12/2025 08:20:13 1001 Bucket errato , tipo 0...
21/12/2025 08:20:13 1001 Bucket errato , tipo 0...
21/12/2025 08:20:13 1001 Bucket errato , tipo 0...
21/12/2025 08:20:01 1001 Bucket errato , tipo 0...
21/12/2025 08:20:00 1001 Bucket errato , tipo 0...
21/12/2025 07:17:15 1001 Bucket errato INVALID_REQUEST, tipo 0...
21/12/2025 07:17:14 1001 Bucket errato INVALID_REQUEST, tipo 0...
21/12/2025 07:17:12 1001 Bucket errato , tipo 0...
21/12/2025 07:17:12 1001 Bucket errato , tipo 0...
21/12/2025 03:18:13 1001 Bucket errato 2160488572794011704, tipo 5...
21/12/2025 03:18:11 1001 Bucket errato , tipo 0...
20/12/2025 23:38:12 1001 Bucket errato INVALID_REQUEST, tipo 0...
20/12/2025 23:38:11 1001 Bucket errato INVALID_REQUEST, tipo 0...
20/12/2025 23:38:09 1001 Bucket errato INVALID_REQUEST, tipo 0...
20/12/2025 23:38:07 1001 Bucket errato INVALID_REQUEST, tipo 0...
20/12/2025 23:38:06 1001 Bucket errato INVALID_REQUEST, tipo 0...
20/12/2025 23:38:04 1001 Bucket errato INVALID_REQUEST, tipo 0...
20/12/2025 23:31:08 1001 Bucket errato , tipo 0...
20/12/2025 23:31:08 1001 Bucket errato , tipo 0...
20/12/2025 23:31:08 1001 Bucket errato , tipo 0...
20/12/2025 23:31:08 1001 Bucket errato , tipo 0...
20/12/2025 23:31:08 1001 Bucket errato , tipo 0...
20/12/2025 23:31:08 1001 Bucket errato , tipo 0...
20/12/2025 23:30:18 1001 Bucket errato , tipo 0...
20/12/2025 23:30:18 1001 Bucket errato , tipo 0...
20/12/2025 23:30:18 1001 Bucket errato , tipo 0...
20/12/2025 23:30:18 1001 Bucket errato , tipo 0...
20/12/2025 23:30:18 1001 Bucket errato , tipo 0...
20/12/2025 23:30:18 1001 Bucket errato , tipo 0...
20/12/2025 23:30:17 1001 Bucket errato , tipo 0...
20/12/2025 23:30:17 1001 Bucket errato , tipo 0...
20/12/2025 23:30:17 1001 Bucket errato , tipo 0...
20/12/2025 23:30:17 1001 Bucket errato , tipo 0...
20/12/2025 23:30:17 1001 Bucket errato , tipo 0...
20/12/2025 23:30:17 1001 Bucket errato , tipo 0...
20/12/2025 23:30:17 1001 Bucket errato , tipo 0...


PS C:\SAFENET\ForEnrollStuff> Get-WinEvent -FilterHashtable @{LogName='System'; Id=1074,6009,6013} -MaxEvents 200 |
>> Sort TimeCreated |
>> Select TimeCreated, Id, Message

TimeCreated           Id Message
-----------           -- -------
01/12/2025 16:56:33 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
01/12/2025 16:56:33 6013 Il periodo di disponibilità del sistema è 10 secondi.
01/12/2025 18:24:17 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
01/12/2025 18:24:41 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
01/12/2025 18:24:41 6013 Il periodo di disponibilità del sistema è 7 secondi.
01/12/2025 18:40:15 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
01/12/2025 18:41:07 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
01/12/2025 18:41:07 6013 Il periodo di disponibilità del sistema è 6 secondi.
01/12/2025 18:42:04 1074 Il processo C:\WINDOWS\system32\winlogon.exe (SPARTACUS) ha iniziato il Riavvia del computer SPARTACUS per conto dell'utente SP...
01/12/2025 18:48:38 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
01/12/2025 18:48:38 6013 Il periodo di disponibilità del sistema è 7 secondi.
01/12/2025 18:48:55 1074 Il processo C:\WINDOWS\system32\winlogon.exe (SPARTACUS) ha iniziato il Riavvia del computer SPARTACUS per conto dell'utente SP...
01/12/2025 19:00:28 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
01/12/2025 19:00:28 6013 Il periodo di disponibilità del sistema è 7 secondi.
01/12/2025 19:00:49 1074 Il processo C:\WINDOWS\system32\winlogon.exe (SPARTACUS) ha iniziato il Riavvia del computer SPARTACUS per conto dell'utente SP...
01/12/2025 19:01:14 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
01/12/2025 19:01:14 6013 Il periodo di disponibilità del sistema è 7 secondi.
01/12/2025 19:01:34 1074 Il processo C:\WINDOWS\system32\winlogon.exe (SPARTACUS) ha iniziato il Spegni del computer SPARTACUS per conto dell'utente SPA...
01/12/2025 19:02:41 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
01/12/2025 19:02:41 6013 Il periodo di disponibilità del sistema è 6 secondi.
01/12/2025 19:03:01 1074 Il processo C:\WINDOWS\system32\winlogon.exe (SPARTACUS) ha iniziato il Riavvia del computer SPARTACUS per conto dell'utente SP...
08/12/2025 12:34:40 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
08/12/2025 12:34:40 6013 Il periodo di disponibilità del sistema è 10 secondi.
08/12/2025 13:03:08 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
08/12/2025 13:03:43 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
08/12/2025 13:03:43 6013 Il periodo di disponibilità del sistema è 10 secondi.
08/12/2025 13:51:55 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
08/12/2025 15:01:20 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
08/12/2025 15:01:20 6013 Il periodo di disponibilità del sistema è 5 secondi.
08/12/2025 15:20:44 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
08/12/2025 15:38:27 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
08/12/2025 15:38:27 6013 Il periodo di disponibilità del sistema è 10 secondi.
08/12/2025 16:13:13 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
08/12/2025 16:13:56 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
08/12/2025 16:13:56 6013 Il periodo di disponibilità del sistema è 7 secondi.
08/12/2025 16:20:59 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
08/12/2025 16:43:08 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
08/12/2025 16:43:08 6013 Il periodo di disponibilità del sistema è 10 secondi.
08/12/2025 17:14:41 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
08/12/2025 17:15:21 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
08/12/2025 17:15:21 6013 Il periodo di disponibilità del sistema è 13 secondi.
08/12/2025 18:00:50 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
08/12/2025 18:01:34 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
08/12/2025 18:01:34 6013 Il periodo di disponibilità del sistema è 11 secondi.
08/12/2025 18:09:49 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
08/12/2025 18:10:25 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
08/12/2025 18:10:25 6013 Il periodo di disponibilità del sistema è 10 secondi.
08/12/2025 18:18:35 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
09/12/2025 10:15:33 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
09/12/2025 10:15:33 6013 Il periodo di disponibilità del sistema è 5 secondi.
09/12/2025 10:33:32 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
09/12/2025 10:34:02 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
09/12/2025 10:34:02 6013 Il periodo di disponibilità del sistema è 7 secondi.
09/12/2025 10:43:08 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
09/12/2025 10:44:16 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
09/12/2025 10:44:16 6013 Il periodo di disponibilità del sistema è 8 secondi.
09/12/2025 10:44:37 1074 Il processo C:\Windows\system32\winlogon.exe (SPARTACUS) ha iniziato il Riavvia del computer SPARTACUS per conto dell'utente SP...
09/12/2025 19:40:54 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
09/12/2025 19:40:54 6013 Il periodo di disponibilità del sistema è 6 secondi.
10/12/2025 08:01:34 1074 Il processo C:\Windows\servicing\TrustedInstaller.exe (SPARTACUS) ha iniziato il Riavvia del computer SPARTACUS per conto dell'...
10/12/2025 08:02:01 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
10/12/2025 08:02:01 6013 Il periodo di disponibilità del sistema è 8 secondi.
10/12/2025 08:03:46 1074 Il processo C:\Windows\servicing\TrustedInstaller.exe (SPARTACUS) ha iniziato il Riavvia del computer SPARTACUS per conto dell'...
10/12/2025 08:04:20 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
10/12/2025 08:04:20 6013 Il periodo di disponibilità del sistema è 9 secondi.
10/12/2025 12:00:01 6013 Il periodo di disponibilità del sistema è 14149 secondi.
10/12/2025 15:24:00 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
11/12/2025 16:05:09 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
11/12/2025 16:05:09 6013 Il periodo di disponibilità del sistema è 8 secondi.
11/12/2025 20:51:47 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
11/12/2025 20:51:47 6013 Il periodo di disponibilità del sistema è 18 secondi.
11/12/2025 23:24:54 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
11/12/2025 23:24:54 6013 Il periodo di disponibilità del sistema è 8 secondi.
12/12/2025 00:38:18 1074 Il processo wininit.exe ha iniziato il Riavvia del computer SPARTACUS per conto dell'utente  a causa del motivo seguente: Impos...
12/12/2025 00:39:43 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
12/12/2025 00:39:43 6013 Il periodo di disponibilità del sistema è 8 secondi.
12/12/2025 11:59:59 6013 Il periodo di disponibilità del sistema è 40825 secondi.
12/12/2025 12:00:00 6013 Il periodo di disponibilità del sistema è 40826 secondi.
12/12/2025 17:46:59 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
13/12/2025 13:13:06 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
13/12/2025 13:13:06 6013 Il periodo di disponibilità del sistema è 6 secondi.
13/12/2025 15:51:22 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
14/12/2025 00:59:58 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
14/12/2025 00:59:58 6013 Il periodo di disponibilità del sistema è 6 secondi.
14/12/2025 01:55:23 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
14/12/2025 05:43:58 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
14/12/2025 05:43:58 6013 Il periodo di disponibilità del sistema è 7 secondi.
14/12/2025 06:26:32 1074 Il processo C:\Windows\System32\mstsc.exe (SPARTACUS) ha iniziato il Riavvia del computer SPARTACUS per conto dell'utente SPART...
14/12/2025 06:29:39 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
14/12/2025 06:29:39 6013 Il periodo di disponibilità del sistema è 7 secondi.
14/12/2025 08:04:46 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
14/12/2025 08:05:11 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
14/12/2025 08:05:11 6013 Il periodo di disponibilità del sistema è 7 secondi.
14/12/2025 10:24:41 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
14/12/2025 19:39:28 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
14/12/2025 19:39:28 6013 Il periodo di disponibilità del sistema è 6 secondi.
14/12/2025 22:44:51 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
14/12/2025 23:15:03 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
14/12/2025 23:15:03 6013 Il periodo di disponibilità del sistema è 6 secondi.
14/12/2025 23:15:12 1074 Il processo C:\Windows\system32\winlogon.exe (SPARTACUS) ha iniziato il Riavvia del computer SPARTACUS per conto dell'utente NT...
14/12/2025 23:16:58 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
14/12/2025 23:16:58 6013 Il periodo di disponibilità del sistema è 6 secondi.
14/12/2025 23:17:16 1074 Il processo C:\Windows\system32\winlogon.exe (SPARTACUS) ha iniziato il Riavvia del computer SPARTACUS per conto dell'utente NT...
14/12/2025 23:18:23 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
14/12/2025 23:18:23 6013 Il periodo di disponibilità del sistema è 7 secondi.
14/12/2025 23:27:59 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
14/12/2025 23:28:57 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
14/12/2025 23:28:57 6013 Il periodo di disponibilità del sistema è 7 secondi.
15/12/2025 12:00:00 6013 Il periodo di disponibilità del sistema è 45069 secondi.
15/12/2025 17:12:36 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
15/12/2025 17:51:15 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
15/12/2025 17:51:15 6013 Il periodo di disponibilità del sistema è 9 secondi.
15/12/2025 21:17:14 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
15/12/2025 23:57:24 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
15/12/2025 23:57:24 6013 Il periodo di disponibilità del sistema è 8 secondi.
16/12/2025 02:13:02 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
16/12/2025 02:13:02 6013 Il periodo di disponibilità del sistema è 7 secondi.
16/12/2025 02:13:54 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
16/12/2025 02:15:29 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
16/12/2025 02:15:29 6013 Il periodo di disponibilità del sistema è 6 secondi.
16/12/2025 04:30:27 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
16/12/2025 04:32:36 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
16/12/2025 04:32:36 6013 Il periodo di disponibilità del sistema è 6 secondi.
16/12/2025 04:39:31 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
16/12/2025 04:47:02 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
16/12/2025 04:47:02 6013 Il periodo di disponibilità del sistema è 6 secondi.
16/12/2025 06:04:39 1074 Il processo C:\Windows\uus\packages\preview\AMD64\MoNotificationUx.exe (SPARTACUS) ha iniziato il Riavvia del computer SPARTACU...
16/12/2025 06:05:48 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
16/12/2025 06:05:48 6013 Il periodo di disponibilità del sistema è 8 secondi.
16/12/2025 12:00:00 6013 Il periodo di disponibilità del sistema è 21259 secondi.
16/12/2025 15:00:56 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
17/12/2025 05:09:19 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
17/12/2025 05:09:19 6013 Il periodo di disponibilità del sistema è 8 secondi.
17/12/2025 12:00:00 6013 Il periodo di disponibilità del sistema è 24649 secondi.
17/12/2025 16:57:27 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
17/12/2025 22:29:34 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
17/12/2025 22:29:34 6013 Il periodo di disponibilità del sistema è 6 secondi.
18/12/2025 00:52:01 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
18/12/2025 00:52:32 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
18/12/2025 00:52:32 6013 Il periodo di disponibilità del sistema è 9 secondi.
18/12/2025 12:00:00 6013 Il periodo di disponibilità del sistema è 40056 secondi.
18/12/2025 12:57:31 1074 Il processo wininit.exe ha iniziato il Riavvia del computer SPARTACUS per conto dell'utente  a causa del motivo seguente: Impos...
18/12/2025 12:58:56 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
18/12/2025 12:58:56 6013 Il periodo di disponibilità del sistema è 8 secondi.
18/12/2025 13:18:12 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
18/12/2025 13:18:46 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
18/12/2025 13:18:46 6013 Il periodo di disponibilità del sistema è 8 secondi.
18/12/2025 13:47:38 1074 Il processo C:\WINDOWS\system32\shutdown.exe (SPARTACUS) ha iniziato il Riavvia del computer SPARTACUS per conto dell'utente SP...
18/12/2025 13:48:01 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
18/12/2025 13:48:01 6013 Il periodo di disponibilità del sistema è 7 secondi.
18/12/2025 15:30:30 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
18/12/2025 18:04:39 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
18/12/2025 18:04:39 6013 Il periodo di disponibilità del sistema è 6 secondi.
18/12/2025 20:00:30 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
18/12/2025 20:01:44 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
18/12/2025 20:01:44 6013 Il periodo di disponibilità del sistema è 8 secondi.
18/12/2025 20:03:29 1074 Il processo C:\Windows\servicing\TrustedInstaller.exe (SPARTACUS) ha iniziato il Riavvia del computer SPARTACUS per conto dell'...
18/12/2025 20:04:04 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
18/12/2025 20:04:04 6013 Il periodo di disponibilità del sistema è 8 secondi.
18/12/2025 20:05:31 1074 Il processo C:\Windows\system32\winlogon.exe (SPARTACUS) ha iniziato il Arresta il sistema del computer SPARTACUS per conto del...
18/12/2025 21:57:08 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
18/12/2025 21:57:08 6013 Il periodo di disponibilità del sistema è 6 secondi.
19/12/2025 03:58:53 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
19/12/2025 14:21:30 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
19/12/2025 14:21:30 6013 Il periodo di disponibilità del sistema è 7 secondi.
19/12/2025 16:30:48 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
19/12/2025 20:55:03 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
19/12/2025 20:55:03 6013 Il periodo di disponibilità del sistema è 6 secondi.
19/12/2025 22:14:03 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
19/12/2025 22:15:22 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
19/12/2025 22:15:22 6013 Il periodo di disponibilità del sistema è 6 secondi.
20/12/2025 00:14:43 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
20/12/2025 00:15:56 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
20/12/2025 00:15:56 6013 Il periodo di disponibilità del sistema è 8 secondi.
20/12/2025 01:08:52 1074 Il processo C:\Windows\system32\winlogon.exe (SPARTACUS) ha iniziato il Riavvia del computer SPARTACUS per conto dell'utente SP...
20/12/2025 16:28:56 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
20/12/2025 16:28:56 6013 Il periodo di disponibilità del sistema è 12 secondi.
20/12/2025 16:29:11 1074 Il processo C:\Windows\system32\winlogon.exe (SPARTACUS) ha iniziato il Riavvia del computer SPARTACUS per conto dell'utente NT...
20/12/2025 22:15:57 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
20/12/2025 22:15:57 6013 Il periodo di disponibilità del sistema è 8 secondi.
20/12/2025 22:36:32 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
20/12/2025 23:28:07 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
20/12/2025 23:28:07 6013 Il periodo di disponibilità del sistema è 6 secondi.
21/12/2025 06:45:17 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
21/12/2025 06:55:01 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
21/12/2025 06:55:01 6013 Il periodo di disponibilità del sistema è 9 secondi.
21/12/2025 06:55:18 1074 Il processo C:\Windows\system32\winlogon.exe (SPARTACUS) ha iniziato il Riavvia del computer SPARTACUS per conto dell'utente NT...
21/12/2025 07:15:03 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
21/12/2025 07:15:03 6013 Il periodo di disponibilità del sistema è 9 secondi.
21/12/2025 08:17:21 1074 Il processo msiexec.exe ha iniziato il Riavvia del computer SPARTACUS per conto dell'utente NT AUTHORITY\SYSTEM a causa del mot...
21/12/2025 08:17:50 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
21/12/2025 08:17:50 6013 Il periodo di disponibilità del sistema è 9 secondi.
21/12/2025 10:09:45 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
21/12/2025 10:10:26 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
21/12/2025 10:10:26 6013 Il periodo di disponibilità del sistema è 8 secondi.
21/12/2025 11:59:59 6013 Il periodo di disponibilità del sistema è 6582 secondi.
21/12/2025 12:00:00 6013 Il periodo di disponibilità del sistema è 6583 secondi.
21/12/2025 19:26:43 1074 Il processo C:\Windows\system32\winlogon.exe (SPARTACUS) ha iniziato il Spegni del computer SPARTACUS per conto dell'utente SPA...
21/12/2025 22:45:53 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
21/12/2025 22:45:53 6013 Il periodo di disponibilità del sistema è 6 secondi.


PS C:\SAFENET\ForEnrollStuff>
PS C:\SAFENET\ForEnrollStuff> 17/12/2025 16:57:27 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
>> 17/12/2025 22:29:34 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
In riga:1 car:12
+ 17/12/2025 16:57:27 1074 Il processo C:\WINDOWS\SystemApps\Microsoft. ...
+            ~~~~~~~~
Token '16:57:27' imprevisto nell'espressione o nell'istruzione.
In riga:1 car:156
+ ... ExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
+                                                                          ~
')' di chiusura mancante nell'espressione.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : UnexpectedToken

PS C:\SAFENET\ForEnrollStuff> 17/12/2025 22:29:34 6013 Il periodo di disponibilità del sistema è 6 secondi.
In riga:1 car:12
+ 17/12/2025 22:29:34 6013 Il periodo di disponibilità del sistema è 6  ...
+            ~~~~~~~~
Token '22:29:34' imprevisto nell'espressione o nell'istruzione.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : UnexpectedToken

PS C:\SAFENET\ForEnrollStuff> 18/12/2025 00:52:01 1074 Il processo C:\WINDOWS\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
>> 18/12/2025 00:52:32 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free.
In riga:1 car:12
+ 18/12/2025 00:52:01 1074 Il processo C:\WINDOWS\SystemApps\Microsoft. ...
+            ~~~~~~~~
Token '00:52:01' imprevisto nell'espressione o nell'istruzione.
In riga:1 car:156
+ ... ExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe (SPARTACU...
+                                                                          ~
')' di chiusura mancante nell'espressione.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : UnexpectedToken

PS C:\SAFENET\ForEnrollStuff> 18/12/2025 00:52:32 6013 Il periodo di disponibilità del sistema è 9 secondi.
In riga:1 car:12
+ 18/12/2025 00:52:32 6013 Il periodo di disponibilità del sistema è 9  ...
+            ~~~~~~~~
Token '00:52:32' imprevisto nell'espressione o nell'istruzione.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : UnexpectedToken

PS C:\SAFENET\ForEnrollStuff> 18/12/2025 12:00:00 6013 Il periodo di disponibilità del sistema è 40056 secondi.
In riga:1 car:12
+ 18/12/2025 12:00:00 6013 Il periodo di disponibilità del sistema è 40 ...
+            ~~~~~~~~
Token '12:00:00' imprevisto nell'espressione o nell'istruzione.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : UnexpectedToken

PS C:\SAFENET\ForEnrollStuff> 18/12/2025 12:57:31 1074 Il processo wininit.exe ha iniziato il Riavvia del computer SPARTACUS per conto dell'utente  a causa del motivo seguente: Impos...
>> 18/12/2025 12:58:56 6009 Microsoft (R) Windows (R) 10.00. 26200  Multiprocessor Free
>>
>>
>> Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 2000 |
>> Where-Object { $_.Message -match "EncodedCommand|IEX|DownloadString|Invoke-WebRequest|curl|bitsadmin|wevtutil|Clear-EventLog" } |
>> Select TimeCreated, Id, Message
>> ^C
PS C:\SAFENET\ForEnrollStuff> ^C
PS C:\SAFENET\ForEnrollStuff> ^C
PS C:\SAFENET\ForEnrollStuff> Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 2000 |
>> Where-Object { $_.Message -match "EncodedCommand|IEX|DownloadString|Invoke-WebRequest|curl|bitsadmin|wevtutil|Clear-EventLog" } |
>> Select TimeCreated, Id, Message

TimeCreated           Id Message
-----------           -- -------
21/12/2025 23:17:15 4104 Creazione del testo di Scriptblock (1 di 1):...
21/12/2025 23:03:16 4104 Creazione del testo di Scriptblock (1 di 1):...
21/12/2025 23:03:16 4104 Creazione del testo di Scriptblock (1 di 1):...
21/12/2025 23:03:15 4104 Creazione del testo di Scriptblock (1 di 1):...
21/12/2025 23:03:15 4104 Creazione del testo di Scriptblock (1 di 1):...


PS C:\SAFENET\ForEnrollStuff> wevtutil sl Security /ms:1073741824
PS C:\SAFENET\ForEnrollStuff> wevtutil sl System   /ms:1073741824
PS C:\SAFENET\ForEnrollStuff> wevtutil sl Application /ms:1073741824
PS C:\SAFENET\ForEnrollStuff> wevtutil gl Security | findstr /i maxSize
  maxSize: 1073741824
PS C:\SAFENET\ForEnrollStuff> Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001} -MaxEvents 50 |
>> Select TimeCreated, ProviderName, Message

TimeCreated         ProviderName                               Message
-----------         ------------                               -------
17/12/2025 05:09:19 Microsoft-Windows-WER-SystemErrorReporting Il computer è stato riavviato da un controllo errori. Controllo errori: 0x000000ef (0xfff...
16/12/2025 02:13:01 Microsoft-Windows-WER-SystemErrorReporting Il computer è stato riavviato da un controllo errori. Controllo errori: 0x000000ef (0xfff...
10/12/2025 08:00:53 Microsoft-Windows-WER-SystemErrorReporting Il computer è stato riavviato da un controllo errori. Controllo errori: 0x000000ef (0xfff...
01/12/2025 04:22:07 Microsoft-Windows-WER-SystemErrorReporting Il computer è stato riavviato da un controllo errori. Controllo errori: 0x000000ef (0xfff...
01/12/2025 02:34:24 Microsoft-Windows-WER-SystemErrorReporting Il computer è stato riavviato da un controllo errori. Controllo errori: 0x000000ef (0xfff...
30/11/2025 04:49:00 Microsoft-Windows-WER-SystemErrorReporting Il computer è stato riavviato da un controllo errori. Controllo errori: 0x000000ef (0xfff...
29/11/2025 21:40:24 Microsoft-Windows-WER-SystemErrorReporting Il computer è stato riavviato da un controllo errori. Controllo errori: 0x000000ef (0xfff...
28/11/2025 19:06:57 Microsoft-Windows-WER-SystemErrorReporting Il computer è stato riavviato da un controllo errori. Controllo errori: 0x000000ef (0xfff...
24/11/2025 12:33:04 Microsoft-Windows-WER-SystemErrorReporting Il computer è stato riavviato da un controllo errori. Controllo errori: 0x000000ef (0xfff...


PS C:\SAFENET\ForEnrollStuff> # Ultimi 20 scriptblock 4104, con testo completo
PS C:\SAFENET\ForEnrollStuff> Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath "*[System[(EventID=4104)]]" -MaxEvents 20 |
>> ForEach-Object {
>>   [PSCustomObject]@{
>>     TimeCreated = $_.TimeCreated
>>     Id          = $_.Id
>>     ScriptText  = ($_.Properties[2].Value)
>>   }
>> } | Format-List


TimeCreated : 22/12/2025 00:03:43
Id          : 4104
ScriptText  : { $_.Message -match "EncodedCommand|IEX|DownloadString|Invoke-WebRequest|curl|bitsadmin|wevtutil|Clear-EventLog" }

TimeCreated : 22/12/2025 00:03:43
Id          : 4104
ScriptText  : Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 2000 |
              Where-Object { $_.Message -match "EncodedCommand|IEX|DownloadString|Invoke-WebRequest|curl|bitsadmin|wevtutil|Clear-EventLog" } |
              Select TimeCreated, Id, Message

TimeCreated : 21/12/2025 23:17:15
Id          : 4104
ScriptText  : <#
                ForensicManager.ps1
                - Menu interattivo
                - Richiama il collector precedente
                - Aggiunge COMPLIANCE + ANALYSIS (log ranges, config, bytes disponibili, stato canali)
                - Fix gestione date (Locale + UTC, naming coerente)
              #>

              Set-StrictMode -Version Latest
              $ErrorActionPreference = "Stop"

              function Test-IsAdmin {
                  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
                  $p  = New-Object Security.Principal.WindowsPrincipal($id)
                  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
              }

              function Get-LocalTimestamp { Get-Date -Format "yyyy-MM-dd_HH-mm-ss" }
              function Get-UTCTimestamp   { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }

              function New-DirectoryIfMissing([string]$Path) {
                  if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path | Out-Null }
              }

              function Write-Section([string]$Title) {
                  Write-Host ""
                  Write-Host ("=" * 78) -ForegroundColor DarkGray
                  Write-Host ("  " + $Title) -ForegroundColor Cyan
                  Write-Host ("=" * 78) -ForegroundColor DarkGray
              }

              function Get-LogConfigWevtutil([string]$LogName) {
                  # wevtutil gl "<log>" -> parse key: value
                  $raw = & wevtutil gl "$LogName" 2>$null
                  if (-not $raw) { return $null }

                  $map = @{}
                  foreach ($line in $raw) {
                      if ($line -match "^\s*([^:]+)\s*:\s*(.*)\s*$") {
                          $k = $matches[1].Trim()
                          $v = $matches[2].Trim()
                          $map[$k] = $v
                      }
                  }

                  # MaxSize from maxSize; current size non sempre disponibile qui, quindi lo stimiamo da file .evtx quando possibile
                  $enabled = $map["enabled"]
                  $maxSize = $map["maxSize"]
                  $ret     = $map["retention"]
                  $autoBk  = $map["autoBackup"]

                  [pscustomobject]@{
                      LogName     = $LogName
                      EnabledText = $enabled
                      Enabled     = ($enabled -match "true")
                      MaxSizeRaw  = $maxSize
                      MaxSizeBytes = if ($maxSize -match "^\d+$") { [int64]$maxSize } else { $null }
                      Retention   = $ret
                      AutoBackup  = $autoBk
                      Raw         = $map
                  }
              }

              function Get-LogRanges([string]$LogName) {
                  try {
                      $oldest = (Get-WinEvent -LogName $LogName -Oldest -MaxEvents 1).TimeCreated.ToUniversalTime().ToString("o")
                      $latest = (Get-WinEvent -LogName $LogName -MaxEvents 1).TimeCreated.ToUniversalTime().ToString("o")
                      return @{ OldestUTC = $oldest; LatestUTC = $latest; Error = $null }
                  } catch {
                      return @{ OldestUTC = $null; LatestUTC = $null; Error = $_.Exception.Message }
                  }
              }

              function Get-EvtxFileSizeBytes([string]$LogName) {
                  # Prova a risolvere il path del file del log
                  try {
                      $p = (Get-WinEvent -ListLog $LogName).LogFilePath
                      if ($p -and (Test-Path $p)) {
                          return (Get-Item $p).Length
                      }
                      return $null
                  } catch { return $null }
              }

              function Invoke-ComplianceAnalysis([string]$OutDir) {
                  New-DirectoryIfMissing $OutDir

                  $analysisStamp = Get-LocalTimestamp
                  $analysisUtc   = Get-UTCTimestamp
                  $computer      = $env:COMPUTERNAME
                  $isAdmin       = Test-IsAdmin

                  Write-Section "Compliance + Analysis snapshot ($analysisStamp)  |  UTC $analysisUtc"
                  Write-Host "Computer: $computer"
                  Write-Host "Admin:    $isAdmin" -ForegroundColor Yellow

                  # Target logs (aggiungine quanti vuoi)
                  $logs = @(
                      "Security",
                      "System",
                      "Application",
                      "Microsoft-Windows-PowerShell/Operational",
                      "Microsoft-Windows-TaskScheduler/Operational",
                      "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin"
                  )

                  $logReport = @()
                  foreach ($ln in $logs) {
                      $cfg    = Get-LogConfigWevtutil $ln
                      $ranges = Get-LogRanges $ln

                      $curSize = Get-EvtxFileSizeBytes $ln
                      $maxSize = if ($cfg) { $cfg.MaxSizeBytes } else { $null }
                      $freeB   = if ($maxSize -and $curSize) { [int64]($maxSize - $curSize) } else { $null }

                      $logReport += [pscustomobject]@{
                          LogName            = $ln
                          Enabled            = if ($cfg) { $cfg.Enabled } else { $null }
                          EnabledText        = if ($cfg) { $cfg.EnabledText } else { $null }
                          Retention          = if ($cfg) { $cfg.Retention } else { $null }
                          AutoBackup         = if ($cfg) { $cfg.AutoBackup } else { $null }
                          MaxSizeBytes       = $maxSize
                          CurrentSizeBytes   = $curSize
                          FreeBytesEstimate  = $freeB
                          OldestEventTimeUTC = $ranges.OldestUTC
                          LatestEventTimeUTC = $ranges.LatestUTC
                          Error              = $ranges.Error
                      }
                  }

                  # Local users quick check (Guest ecc.)
                  $users = @()
                  try {
                      $users = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, Description
                  } catch {
                      # su alcune build/policy puÃ² fallire
                      $users = @()
                  }

                  $guest = $users | Where-Object { $_.Name -ieq "Guest" } | Select-Object -First 1
                  $flags = [ordered]@{
                      "SecurityLogReadable"      = -not (($logReport | Where-Object LogName -eq "Security").Error)
                      "TaskSchedulerOperational" = (($logReport | Where-Object LogName -eq "Microsoft-Windows-TaskScheduler/Operational").Enabled -eq
              $true)
                      "GuestEnabled"             = if ($guest) { [bool]$guest.Enabled } else { $null }
                  }

                  # Write outputs
                  $metaPath = Join-Path $OutDir ("analysis_log_metadata_$analysisStamp.json")
                  $userPath = Join-Path $OutDir ("analysis_local_users_$analysisStamp.csv")
                  $sumPath  = Join-Path $OutDir ("analysis_summary_$analysisStamp.json")

                  $logReport | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 $metaPath
                  if ($users.Count -gt 0) { $users | Export-Csv -NoTypeInformation -Encoding UTF8 $userPath }

                  $summary = [pscustomobject]@{
                      ComputerName   = $computer
                      CollectionLocal= $analysisStamp
                      CollectionUTC  = $analysisUtc
                      IsAdmin        = $isAdmin
                      Flags          = $flags
                      LogsCount      = $logReport.Count
                      UsersCount     = $users.Count
                  }
                  $summary | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 $sumPath

                  Write-Host ""
                  Write-Host "Saved:" -ForegroundColor Green
                  Write-Host " - $metaPath"
                  Write-Host " - $sumPath"
                  if ($users.Count -gt 0) { Write-Host " - $userPath" }

                  # Punchy recommendations
                  Write-Host ""
                  Write-Host "Immediate findings (actionable):" -ForegroundColor Magenta
                  if (-not $flags.SecurityLogReadable) {
                      Write-Host " - Security log NOT readable -> run as Admin / check policy ACL." -ForegroundColor Yellow
                  }
                  if (-not $flags.TaskSchedulerOperational) {
                      Write-Host " - TaskScheduler/Operational DISABLED -> enable for persistence hunting." -ForegroundColor Yellow
                  }
                  if ($flags.GuestEnabled -eq $true) {
                      Write-Host " - Guest is ENABLED -> this is unusual; verify who/why." -ForegroundColor Yellow
                  }
              }

              function Enable-UsefulChannels {
                  Write-Section "Enable useful channels (minimal, reversible)"
                  $targets = @(
                      "Microsoft-Windows-TaskScheduler/Operational",
                      "Microsoft-Windows-WMI-Activity/Operational"
                  )
                  foreach ($t in $targets) {
                      try {
                          & wevtutil sl "$t" /e:true | Out-Null
                          Write-Host "Enabled: $t" -ForegroundColor Green
                      } catch {
                          Write-Host "Failed: $t  -> $($_.Exception.Message)" -ForegroundColor Red
                      }
                  }
              }

              function Invoke-Collector([string]$CollectorScript, [string]$BaseOutDir) {
                  if (-not (Test-Path $CollectorScript)) {
                      throw "Collector script not found: $CollectorScript"
                  }
                  Write-Section "Running collector: $CollectorScript"
                  New-DirectoryIfMissing $BaseOutDir

                  # Il collector Ã¨ interattivo: lo richiamiamo "as-is"
                  & powershell.exe -ExecutionPolicy Bypass -File $CollectorScript
              }

              # -------------------- MAIN --------------------
              $ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
              $CollectorScript = Join-Path $ScriptRoot "Collect_ByUser_Temp_Enroll.ps1"

              $BaseOutDir = Join-Path $ScriptRoot ("ForensicOut_" + $env:COMPUTERNAME)
              New-DirectoryIfMissing $BaseOutDir

              while ($true) {
                  Write-Host ""
                  $menuStamp = Get-LocalTimestamp
                  Write-Host "Forensic Manager  |  $menuStamp  |  Out: $BaseOutDir" -ForegroundColor Cyan
                  Write-Host "1) Run previous collector (interactive)"
                  Write-Host "2) Compliance + Analysis snapshot (log ranges/config/free bytes/users)"
                  Write-Host "3) Enable useful log channels (TaskScheduler/WMI)"
                  Write-Host "4) Show paths"
                  Write-Host "0) Exit"
                  $choice = Read-Host "Select"

                  switch ($choice) {
                      "1" { Invoke-Collector -CollectorScript $CollectorScript -BaseOutDir $BaseOutDir }
                      "2" {
                          $analysisStamp = Get-LocalTimestamp
                          $out = Join-Path $BaseOutDir ("Analysis_" + $analysisStamp)
                          Invoke-ComplianceAnalysis -OutDir $out
                      }
                      "3" { Enable-UsefulChannels }
                      "4" {
                          Write-Host "ScriptRoot: $ScriptRoot"
                          Write-Host "Collector:  $CollectorScript"
                          Write-Host "OutDir:     $BaseOutDir"
                      }
                      "0" { break }
                      default { Write-Host "Invalid choice." -ForegroundColor Yellow }
                  }
              }


TimeCreated : 21/12/2025 23:03:19
Id          : 4104
ScriptText  : 32'; Bindings = 'Error'; Value = $null; IsValuePresent = $false }
                    $__cmdletization_methodInvocationInfo = [Microsoft.PowerShell.Cmdletization.MethodInvocationInfo]::new('SetByParams',
              $__cmdletization_methodParameters, $__cmdletization_returnValue)
                    $__cmdletization_objectModelWrapper.ProcessRecord($__cmdletization_methodInvocationInfo)
                      }
                      { @('Xml') -contains $_ } {
                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Xml')) {
                        [object]$__cmdletization_value = ${Xml}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Xml'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Xml'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Cluster')) {
                        [object]$__cmdletization_value = ${Cluster}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Cluster'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Cluster'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('TaskName')) {
                        [object]$__cmdletization_value = ${TaskName}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'CmdletOutput'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'Out'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_ClusteredScheduledTask'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                    $__cmdletization_returnValue = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{ Name = 'ReturnValue'; ParameterType =
              'System.Int32'; Bindings = 'Error'; Value = $null; IsValuePresent = $false }
                    $__cmdletization_methodInvocationInfo = [Microsoft.PowerShell.Cmdletization.MethodInvocationInfo]::new('SetByXml',
              $__cmdletization_methodParameters, $__cmdletization_returnValue)
                    $__cmdletization_objectModelWrapper.ProcessRecord($__cmdletization_methodInvocationInfo)
                      }
                  }

                          }
                      }
                      catch
                      {
                          $__cmdletization_exceptionHasBeenThrown = $true
                          throw
                      }
                  }


                  End {
                      try
                      {
                          if (-not $__cmdletization_exceptionHasBeenThrown)
                          {
                              $__cmdletization_objectModelWrapper.EndProcessing()
                          }
                      }
                      catch
                      {
                          throw
                      }
                  }

                  # .EXTERNALHELP PS_ClusteredScheduledTask_v1.0.cdxml-Help.xml
              }
              Microsoft.PowerShell.Core\Export-ModuleMember -Function 'Set-ClusteredScheduledTask' -Alias '*'


              function Unregister-ClusteredScheduledTask
              {
                  [CmdletBinding(PositionalBinding=$false)]


                  param(

                  [Parameter(ParameterSetName='Name', Position=1)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [string]
                  ${Cluster},

                  [Parameter(ParameterSetName='Name', Mandatory=$true, Position=0)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [string]
                  ${TaskName},

                  [Parameter(ParameterSetName='Object', Position=0, ValueFromPipeline=$true)]
                  [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_ClusteredScheduledTask')]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [ciminstance]
                  ${InputObject},

                  [Parameter(ParameterSetName='Name')]
                  [Parameter(ParameterSetName='Object')]
                  [Alias('Session')]
                  [ValidateNotNullOrEmpty()]
                  [CimSession[]]
                  ${CimSession},

                  [Parameter(ParameterSetName='Name')]
                  [Parameter(ParameterSetName='Object')]
                  [int]
                  ${ThrottleLimit},

                  [Parameter(ParameterSetName='Name')]
                  [Parameter(ParameterSetName='Object')]
                  [switch]
                  ${AsJob})

                  DynamicParam {
                      try
                      {
                          if (-not $__cmdletization_exceptionHasBeenThrown)
                          {
                              $__cmdletization_objectModelWrapper = $script:ObjectModelWrapper::new()
                              $__cmdletization_objectModelWrapper.Initialize($PSCmdlet, $script:ClassName, $script:ClassVersion, $script:ModuleVersion,
              $script:PrivateData)

                              if ($__cmdletization_objectModelWrapper -is [System.Management.Automation.IDynamicParameters])
                              {
                                  ([System.Management.Automation.IDynamicParameters]$__cmdletization_objectModelWrapper).GetDynamicParameters()
                              }
                          }
                      }
                      catch
                      {
                          $__cmdletization_exceptionHasBeenThrown = $true
                          throw
                      }
                  }

                  Begin {
                      $__cmdletization_exceptionHasBeenThrown = $false
                      try
                      {
                          __cmdletization_BindCommonParameters $__cmdletization_objectModelWrapper $PSBoundParameters
                          $__cmdletization_objectModelWrapper.BeginProcessing()
                      }
                      catch
                      {
                          $__cmdletization_exceptionHasBeenThrown = $true
                          throw
                      }
                  }


                  Process {
                      try
                      {
                          if (-not $__cmdletization_exceptionHasBeenThrown)
                          {
                    $__cmdletization_methodParameters = [System.Collections.Generic.List[Microsoft.PowerShell.Cmdletization.MethodParameter]]::new()

                    switch -exact ($PSCmdlet.ParameterSetName) {
                      { @('Name') -contains $_ } {
                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Cluster')) {
                        [object]$__cmdletization_value = ${Cluster}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Cluster'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Cluster'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('TaskName')) {
                        [object]$__cmdletization_value = ${TaskName}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                    $__cmdletization_returnValue = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{ Name = 'ReturnValue'; ParameterType =
              'System.Int32'; Bindings = 'Error'; Value = $null; IsValuePresent = $false }
                    $__cmdletization_methodInvocationInfo = [Microsoft.PowerShell.Cmdletization.MethodInvocationInfo]::new('UnregisterByName',
              $__cmdletization_methodParameters, $__cmdletization_returnValue)
                    $__cmdletization_objectModelWrapper.ProcessRecord($__cmdletization_methodInvocationInfo)
                      }
                      { @('Object') -contains $_ } {
                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('InputObject')) {
                        [object]$__cmdletization_value = ${InputObject}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'InputObject'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'InputObject'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_ClusteredScheduledTask'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                    $__cmdletization_returnValue = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{ Name = 'ReturnValue'; ParameterType =
              'System.Int32'; Bindings = 'Error'; Value = $null; IsValuePresent = $false }
                    $__cmdletization_methodInvocationInfo = [Microsoft.PowerShell.Cmdletization.MethodInvocationInfo]::new('UnregisterByObject',
              $__cmdletization_methodParameters, $__cmdletization_returnValue)
                    $__cmdletization_objectModelWrapper.ProcessRecord($__cmdletization_methodInvocationInfo)
                      }
                  }

                          }
                      }
                      catch
                      {
                          $__cmdletization_exceptionHasBeenThrown = $true
                          throw
                      }
                  }


                  End {
                      try
                      {
                          if (-not $__cmdletization_exceptionHasBeenThrown)
                          {
                              $__cmdletization_objectModelWrapper.EndProcessing()
                          }
                      }
                      catch
                      {
                          throw
                      }
                  }

                  # .EXTERNALHELP PS_ClusteredScheduledTask_v1.0.cdxml-Help.xml
              }
              Microsoft.PowerShell.Core\Export-ModuleMember -Function 'Unregister-ClusteredScheduledTask' -Alias '*'



TimeCreated : 21/12/2025 23:03:19
Id          : 4104
ScriptText  :    ${CimSession},

                  [Parameter(ParameterSetName='Object')]
                  [Parameter(ParameterSetName='Params')]
                  [Parameter(ParameterSetName='Xml')]
                  [int]
                  ${ThrottleLimit},

                  [Parameter(ParameterSetName='Object')]
                  [Parameter(ParameterSetName='Params')]
                  [Parameter(ParameterSetName='Xml')]
                  [switch]
                  ${AsJob})

                  DynamicParam {
                      try
                      {
                          if (-not $__cmdletization_exceptionHasBeenThrown)
                          {
                              $__cmdletization_objectModelWrapper = $script:ObjectModelWrapper::new()
                              $__cmdletization_objectModelWrapper.Initialize($PSCmdlet, $script:ClassName, $script:ClassVersion, $script:ModuleVersion,
              $script:PrivateData)

                              if ($__cmdletization_objectModelWrapper -is [System.Management.Automation.IDynamicParameters])
                              {
                                  ([System.Management.Automation.IDynamicParameters]$__cmdletization_objectModelWrapper).GetDynamicParameters()
                              }
                          }
                      }
                      catch
                      {
                          $__cmdletization_exceptionHasBeenThrown = $true
                          throw
                      }
                  }

                  Begin {
                      $__cmdletization_exceptionHasBeenThrown = $false
                      try
                      {
                          __cmdletization_BindCommonParameters $__cmdletization_objectModelWrapper $PSBoundParameters
                          $__cmdletization_objectModelWrapper.BeginProcessing()
                      }
                      catch
                      {
                          $__cmdletization_exceptionHasBeenThrown = $true
                          throw
                      }
                  }


                  Process {
                      try
                      {
                          if (-not $__cmdletization_exceptionHasBeenThrown)
                          {
                    $__cmdletization_methodParameters = [System.Collections.Generic.List[Microsoft.PowerShell.Cmdletization.MethodParameter]]::new()

                    switch -exact ($PSCmdlet.ParameterSetName) {
                      { @('Object') -contains $_ } {
                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('TaskName')) {
                        [object]$__cmdletization_value = ${TaskName}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Cluster')) {
                        [object]$__cmdletization_value = ${Cluster}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Cluster'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Cluster'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('InputObject')) {
                        [object]$__cmdletization_value = ${InputObject}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'InputObject'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'InputObject'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'CmdletOutput'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'Out'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_ClusteredScheduledTask'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                    $__cmdletization_returnValue = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{ Name = 'ReturnValue'; ParameterType =
              'System.Int32'; Bindings = 'Error'; Value = $null; IsValuePresent = $false }
                    $__cmdletization_methodInvocationInfo = [Microsoft.PowerShell.Cmdletization.MethodInvocationInfo]::new('SetByObject',
              $__cmdletization_methodParameters, $__cmdletization_returnValue)
                    $__cmdletization_objectModelWrapper.ProcessRecord($__cmdletization_methodInvocationInfo)
                      }
                      { @('Params') -contains $_ } {
                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Action')) {
                        [object]$__cmdletization_value = ${Action}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Action'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance[]'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Action'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance[]'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskAction'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Settings')) {
                        [object]$__cmdletization_value = ${Settings}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Settings'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Settings'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskSettings'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Cluster')) {
                        [object]$__cmdletization_value = ${Cluster}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Cluster'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Cluster'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('TaskName')) {
                        [object]$__cmdletization_value = ${TaskName}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Trigger')) {
                        [object]$__cmdletization_value = ${Trigger}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Trigger'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance[]'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Trigger'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance[]'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskTrigger'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Description')) {
                        [object]$__cmdletization_value = ${Description}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Description'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Description'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'CmdletOutput'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'Out'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_ClusteredScheduledTask'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                    $__cmdletization_returnValue = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{ Name = 'ReturnValue'; ParameterType = 'System.Int

TimeCreated : 21/12/2025 23:03:19
Id          : 4104
ScriptText  : werShell.Cmdletization.MethodParameter]@{Name = 'Action'; ParameterType = 'Microsoft.Management.Infrastructure.CimInstance[]'; Bindings =
              'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskAction'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('TaskType')) {
                        [object]$__cmdletization_value = ${TaskType}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskType'; ParameterType =
              'Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.ClusterTaskTypeEnum'; Bindings = 'In'; Value = $__cmdletization_value;
              IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskType'; ParameterType =
              'Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.ClusterTaskTypeEnum'; Bindings = 'In'; Value =
              $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Resource')) {
                        [object]$__cmdletization_value = ${Resource}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Resource'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Resource'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'CmdletOutput'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'Out'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_ClusteredScheduledTask'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                    $__cmdletization_returnValue = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{ Name = 'ReturnValue'; ParameterType =
              'System.Int32'; Bindings = 'Error'; Value = $null; IsValuePresent = $false }
                    $__cmdletization_methodInvocationInfo = [Microsoft.PowerShell.Cmdletization.MethodInvocationInfo]::new('RegisterByParams',
              $__cmdletization_methodParameters, $__cmdletization_returnValue)
                    $__cmdletization_objectModelWrapper.ProcessRecord($__cmdletization_methodInvocationInfo)
                      }
                      { @('Xml') -contains $_ } {
                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Xml')) {
                        [object]$__cmdletization_value = ${Xml}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Xml'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Xml'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('TaskName')) {
                        [object]$__cmdletization_value = ${TaskName}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Cluster')) {
                        [object]$__cmdletization_value = ${Cluster}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Cluster'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Cluster'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('TaskType')) {
                        [object]$__cmdletization_value = ${TaskType}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskType'; ParameterType =
              'Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.ClusterTaskTypeEnum'; Bindings = 'In'; Value = $__cmdletization_value;
              IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskType'; ParameterType =
              'Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.ClusterTaskTypeEnum'; Bindings = 'In'; Value =
              $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Resource')) {
                        [object]$__cmdletization_value = ${Resource}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Resource'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Resource'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'CmdletOutput'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'Out'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_ClusteredScheduledTask'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                    $__cmdletization_returnValue = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{ Name = 'ReturnValue'; ParameterType =
              'System.Int32'; Bindings = 'Error'; Value = $null; IsValuePresent = $false }
                    $__cmdletization_methodInvocationInfo = [Microsoft.PowerShell.Cmdletization.MethodInvocationInfo]::new('RegisterByXml',
              $__cmdletization_methodParameters, $__cmdletization_returnValue)
                    $__cmdletization_objectModelWrapper.ProcessRecord($__cmdletization_methodInvocationInfo)
                      }
                  }

                          }
                      }
                      catch
                      {
                          $__cmdletization_exceptionHasBeenThrown = $true
                          throw
                      }
                  }


                  End {
                      try
                      {
                          if (-not $__cmdletization_exceptionHasBeenThrown)
                          {
                              $__cmdletization_objectModelWrapper.EndProcessing()
                          }
                      }
                      catch
                      {
                          throw
                      }
                  }

                  # .EXTERNALHELP PS_ClusteredScheduledTask_v1.0.cdxml-Help.xml
              }
              Microsoft.PowerShell.Core\Export-ModuleMember -Function 'Register-ClusteredScheduledTask' -Alias '*'


              function Set-ClusteredScheduledTask
              {
                  [CmdletBinding(PositionalBinding=$false)]

                  [OutputType([Microsoft.Management.Infrastructure.CimInstance])][OutputType('Microsoft.Management.Infrastructure.CimInstance#MSFT_Clustere
              dScheduledTask')][OutputType([Microsoft.Management.Infrastructure.CimInstance])][OutputType('Microsoft.Management.Infrastructure.CimInstance#
              MSFT_ClusteredScheduledTask')][OutputType([Microsoft.Management.Infrastructure.CimInstance])][OutputType('Microsoft.Management.Infrastructure
              .CimInstance#MSFT_ClusteredScheduledTask')]
                  param(

                  [Parameter(ParameterSetName='Object', Mandatory=$true, Position=0)]
                  [Parameter(ParameterSetName='Params', Mandatory=$true, Position=0)]
                  [Parameter(ParameterSetName='Xml', Mandatory=$true, Position=0)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [string]
                  ${TaskName},

                  [Parameter(ParameterSetName='Object', Position=2)]
                  [Parameter(ParameterSetName='Params', Position=5)]
                  [Parameter(ParameterSetName='Xml', Position=2)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [string]
                  ${Cluster},

                  [Parameter(ParameterSetName='Object', Mandatory=$true, Position=1, ValueFromPipeline=$true)]
                  [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask')]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [ciminstance]
                  ${InputObject},

                  [Parameter(ParameterSetName='Params', Position=1)]
                  [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskAction')]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [ciminstance[]]
                  ${Action},

                  [Parameter(ParameterSetName='Params', Position=3)]
                  [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskSettings')]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [ciminstance]
                  ${Settings},

                  [Parameter(ParameterSetName='Params', Position=2)]
                  [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskTrigger')]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [ciminstance[]]
                  ${Trigger},

                  [Parameter(ParameterSetName='Params', Position=4)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [string]
                  ${Description},

                  [Parameter(ParameterSetName='Xml', Mandatory=$true, Position=1, ValueFromPipeline=$true)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [string]
                  ${Xml},

                  [Parameter(ParameterSetName='Object')]
                  [Parameter(ParameterSetName='Params')]
                  [Parameter(ParameterSetName='Xml')]
                  [Alias('Session')]
                  [ValidateNotNullOrEmpty()]
                  [CimSession[]]


TimeCreated : 21/12/2025 23:03:19
Id          : 4104
ScriptText  :       $__cmdletization_objectModelWrapper.Initialize($PSCmdlet, $script:ClassName, $script:ClassVersion, $script:ModuleVersion,
              $script:PrivateData)

                              if ($__cmdletization_objectModelWrapper -is [System.Management.Automation.IDynamicParameters])
                              {
                                  ([System.Management.Automation.IDynamicParameters]$__cmdletization_objectModelWrapper).GetDynamicParameters()
                              }
                          }
                      }
                      catch
                      {
                          $__cmdletization_exceptionHasBeenThrown = $true
                          throw
                      }
                  }

                  Begin {
                      $__cmdletization_exceptionHasBeenThrown = $false
                      try
                      {
                          __cmdletization_BindCommonParameters $__cmdletization_objectModelWrapper $PSBoundParameters
                          $__cmdletization_objectModelWrapper.BeginProcessing()
                      }
                      catch
                      {
                          $__cmdletization_exceptionHasBeenThrown = $true
                          throw
                      }
                  }


                  Process {
                      try
                      {
                          if (-not $__cmdletization_exceptionHasBeenThrown)
                          {
                    $__cmdletization_methodParameters = [System.Collections.Generic.List[Microsoft.PowerShell.Cmdletization.MethodParameter]]::new()

                    switch -exact ($PSCmdlet.ParameterSetName) {
                      { @('Object') -contains $_ } {
                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('InputObject')) {
                        [object]$__cmdletization_value = ${InputObject}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'InputObject'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'InputObject'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Cluster')) {
                        [object]$__cmdletization_value = ${Cluster}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Cluster'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Cluster'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('TaskName')) {
                        [object]$__cmdletization_value = ${TaskName}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('TaskType')) {
                        [object]$__cmdletization_value = ${TaskType}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskType'; ParameterType =
              'Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.ClusterTaskTypeEnum'; Bindings = 'In'; Value = $__cmdletization_value;
              IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskType'; ParameterType =
              'Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.ClusterTaskTypeEnum'; Bindings = 'In'; Value =
              $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Resource')) {
                        [object]$__cmdletization_value = ${Resource}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Resource'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Resource'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'CmdletOutput'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'Out'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_ClusteredScheduledTask'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                    $__cmdletization_returnValue = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{ Name = 'ReturnValue'; ParameterType =
              'System.Int32'; Bindings = 'Error'; Value = $null; IsValuePresent = $false }
                    $__cmdletization_methodInvocationInfo = [Microsoft.PowerShell.Cmdletization.MethodInvocationInfo]::new('RegisterByObject',
              $__cmdletization_methodParameters, $__cmdletization_returnValue)
                    $__cmdletization_objectModelWrapper.ProcessRecord($__cmdletization_methodInvocationInfo)
                      }
                      { @('Params') -contains $_ } {
                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('TaskName')) {
                        [object]$__cmdletization_value = ${TaskName}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Settings')) {
                        [object]$__cmdletization_value = ${Settings}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Settings'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Settings'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskSettings'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Description')) {
                        [object]$__cmdletization_value = ${Description}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Description'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Description'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Trigger')) {
                        [object]$__cmdletization_value = ${Trigger}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Trigger'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance[]'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Trigger'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance[]'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskTrigger'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Cluster')) {
                        [object]$__cmdletization_value = ${Cluster}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Cluster'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Cluster'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Action')) {
                        [object]$__cmdletization_value = ${Action}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Action'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance[]'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.Po

TimeCreated : 21/12/2025 23:03:19
Id          : 4104
ScriptText  :
              #requires -version 3.0

              try { Microsoft.PowerShell.Core\Set-StrictMode -Off } catch { }

              $script:MyModule = $MyInvocation.MyCommand.ScriptBlock.Module

              $script:ClassName = 'Root/Microsoft/Windows/TaskScheduler/PS_ClusteredScheduledTask'
              $script:ClassVersion = '1.0'
              $script:ModuleVersion = '1.0'
              $script:ObjectModelWrapper = [Microsoft.PowerShell.Cmdletization.Cim.CimCmdletAdapter]

              $script:PrivateData = [System.Collections.Generic.Dictionary[string,string]]::new()

              Microsoft.PowerShell.Core\Export-ModuleMember -Function @()


              function __cmdletization_BindCommonParameters
              {
                  param(
                      $__cmdletization_objectModelWrapper,
                      $myPSBoundParameters
                  )


                      if ($myPSBoundParameters.ContainsKey('CimSession')) {
                          $__cmdletization_objectModelWrapper.PSObject.Properties['CimSession'].Value = $myPSBoundParameters['CimSession']
                      }


                      if ($myPSBoundParameters.ContainsKey('ThrottleLimit')) {
                          $__cmdletization_objectModelWrapper.PSObject.Properties['ThrottleLimit'].Value = $myPSBoundParameters['ThrottleLimit']
                      }


                      if ($myPSBoundParameters.ContainsKey('AsJob')) {
                          $__cmdletization_objectModelWrapper.PSObject.Properties['AsJob'].Value = $myPSBoundParameters['AsJob']
                      }


              }


              function Get-ClusteredScheduledTask
              {
                  [CmdletBinding(PositionalBinding=$false)]

                  [OutputType([Microsoft.Management.Infrastructure.CimInstance[]])][OutputType('Microsoft.Management.Infrastructure.CimInstance#MSFT_Cluste
              redScheduledTask')]
                  param(

                  [Parameter(ParameterSetName='Get0', Position=0)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [string]
                  ${TaskName},

                  [Parameter(ParameterSetName='Get0', Position=1)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [string]
                  ${Cluster},

                  [Parameter(ParameterSetName='Get0', Position=2)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.ClusterTaskTypeEnum]
                  ${TaskType},

                  [Parameter(ParameterSetName='Get0')]
                  [Alias('Session')]
                  [ValidateNotNullOrEmpty()]
                  [CimSession[]]
                  ${CimSession},

                  [Parameter(ParameterSetName='Get0')]
                  [int]
                  ${ThrottleLimit},

                  [Parameter(ParameterSetName='Get0')]
                  [switch]
                  ${AsJob})

                  DynamicParam {
                      try
                      {
                          if (-not $__cmdletization_exceptionHasBeenThrown)
                          {
                              $__cmdletization_objectModelWrapper = $script:ObjectModelWrapper::new()
                              $__cmdletization_objectModelWrapper.Initialize($PSCmdlet, $script:ClassName, $script:ClassVersion, $script:ModuleVersion,
              $script:PrivateData)

                              if ($__cmdletization_objectModelWrapper -is [System.Management.Automation.IDynamicParameters])
                              {
                                  ([System.Management.Automation.IDynamicParameters]$__cmdletization_objectModelWrapper).GetDynamicParameters()
                              }
                          }
                      }
                      catch
                      {
                          $__cmdletization_exceptionHasBeenThrown = $true
                          throw
                      }
                  }

                  Begin {
                      $__cmdletization_exceptionHasBeenThrown = $false
                      try
                      {
                          __cmdletization_BindCommonParameters $__cmdletization_objectModelWrapper $PSBoundParameters
                          $__cmdletization_objectModelWrapper.BeginProcessing()
                      }
                      catch
                      {
                          $__cmdletization_exceptionHasBeenThrown = $true
                          throw
                      }
                  }


                  Process {
                      try
                      {
                          if (-not $__cmdletization_exceptionHasBeenThrown)
                          {
                    $__cmdletization_methodParameters = [System.Collections.Generic.List[Microsoft.PowerShell.Cmdletization.MethodParameter]]::new()

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('TaskName')) {
                        [object]$__cmdletization_value = ${TaskName}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Cluster')) {
                        [object]$__cmdletization_value = ${Cluster}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Cluster'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Cluster'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('TaskType')) {
                        [object]$__cmdletization_value = ${TaskType}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskType'; ParameterType =
              'Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.ClusterTaskTypeEnum'; Bindings = 'In'; Value = $__cmdletization_value;
              IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskType'; ParameterType =
              'Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.ClusterTaskTypeEnum'; Bindings = 'In'; Value =
              $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'CmdletOutput'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance[]'; Bindings = 'Out'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_ClusteredScheduledTask'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                    $__cmdletization_returnValue = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{ Name = 'ReturnValue'; ParameterType =
              'System.Int32'; Bindings = 'Error'; Value = $null; IsValuePresent = $false }
                    $__cmdletization_methodInvocationInfo = [Microsoft.PowerShell.Cmdletization.MethodInvocationInfo]::new('Get',
              $__cmdletization_methodParameters, $__cmdletization_returnValue)
                    $__cmdletization_objectModelWrapper.ProcessRecord($__cmdletization_methodInvocationInfo)

                          }
                      }
                      catch
                      {
                          $__cmdletization_exceptionHasBeenThrown = $true
                          throw
                      }
                  }


                  End {
                      try
                      {
                          if (-not $__cmdletization_exceptionHasBeenThrown)
                          {
                              $__cmdletization_objectModelWrapper.EndProcessing()
                          }
                      }
                      catch
                      {
                          throw
                      }
                  }

                  # .EXTERNALHELP PS_ClusteredScheduledTask_v1.0.cdxml-Help.xml
              }
              Microsoft.PowerShell.Core\Export-ModuleMember -Function 'Get-ClusteredScheduledTask' -Alias '*'


              function Register-ClusteredScheduledTask
              {
                  [CmdletBinding(PositionalBinding=$false)]

                  [OutputType([Microsoft.Management.Infrastructure.CimInstance])][OutputType('Microsoft.Management.Infrastructure.CimInstance#MSFT_Clustere
              dScheduledTask')][OutputType([Microsoft.Management.Infrastructure.CimInstance])][OutputType('Microsoft.Management.Infrastructure.CimInstance#
              MSFT_ClusteredScheduledTask')][OutputType([Microsoft.Management.Infrastructure.CimInstance])][OutputType('Microsoft.Management.Infrastructure
              .CimInstance#MSFT_ClusteredScheduledTask')]
                  param(

                  [Parameter(ParameterSetName='Object', Mandatory=$true, Position=2, ValueFromPipeline=$true)]
                  [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask')]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [ciminstance]
                  ${InputObject},

                  [Parameter(ParameterSetName='Object', Position=3)]
                  [Parameter(ParameterSetName='Params', Position=6)]
                  [Parameter(ParameterSetName='Xml', Position=3)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [string]
                  ${Cluster},

                  [Parameter(ParameterSetName='Object', Mandatory=$true, Position=0)]
                  [Parameter(ParameterSetName='Params', Mandatory=$true, Position=0)]
                  [Parameter(ParameterSetName='Xml', Mandatory=$true, Position=0)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [string]
                  ${TaskName},

                  [Parameter(ParameterSetName='Object', Position=1)]
                  [Parameter(ParameterSetName='Params', Position=1)]
                  [Parameter(ParameterSetName='Xml', Position=1)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.ClusterTaskTypeEnum]
                  ${TaskType},

                  [Parameter(ParameterSetName='Object', Position=4)]
                  [Parameter(ParameterSetName='Params', Position=7)]
                  [Parameter(ParameterSetName='Xml', Position=4)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [string]
                  ${Resource},

                  [Parameter(ParameterSetName='Params', Position=4)]
                  [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskSettings')]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [ciminstance]
                  ${Settings},

                  [Parameter(ParameterSetName='Params', Position=5)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [string]
                  ${Description},

                  [Parameter(ParameterSetName='Params', Position=3)]
                  [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskTrigger')]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [ciminstance[]]
                  ${Trigger},

                  [Parameter(ParameterSetName='Params', Mandatory=$true, Position=2)]
                  [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskAction')]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [ciminstance[]]
                  ${Action},

                  [Parameter(ParameterSetName='Xml', Mandatory=$true, Position=2, ValueFromPipeline=$true)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [string]
                  ${Xml},

                  [Parameter(ParameterSetName='Object')]
                  [Parameter(ParameterSetName='Params')]
                  [Parameter(ParameterSetName='Xml')]
                  [Alias('Session')]
                  [ValidateNotNullOrEmpty()]
                  [CimSession[]]
                  ${CimSession},

                  [Parameter(ParameterSetName='Object')]
                  [Parameter(ParameterSetName='Params')]
                  [Parameter(ParameterSetName='Xml')]
                  [int]
                  ${ThrottleLimit},

                  [Parameter(ParameterSetName='Object')]
                  [Parameter(ParameterSetName='Params')]
                  [Parameter(ParameterSetName='Xml')]
                  [switch]
                  ${AsJob})

                  DynamicParam {
                      try
                      {
                          if (-not $__cmdletization_exceptionHasBeenThrown)
                          {
                              $__cmdletization_objectModelWrapper = $script:ObjectModelWrapper::new()


TimeCreated : 21/12/2025 23:03:19
Id          : 4104
ScriptText  : ame = 'TaskPath'; ParameterType = 'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('TaskName')) {
                        [object]$__cmdletization_value = ${TaskName}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                    $__cmdletization_returnValue = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{ Name = 'ReturnValue'; ParameterType =
              'System.Int32'; Bindings = 'Error'; Value = $null; IsValuePresent = $false }
                    $__cmdletization_methodInvocationInfo = [Microsoft.PowerShell.Cmdletization.MethodInvocationInfo]::new('StopByPath',
              $__cmdletization_methodParameters, $__cmdletization_returnValue)
                    $__cmdletization_objectModelWrapper.ProcessRecord($__cmdletization_methodInvocationInfo)
                      }
                  }

                          }
                      }
                      catch
                      {
                          $__cmdletization_exceptionHasBeenThrown = $true
                          throw
                      }
                  }


                  End {
                      try
                      {
                          if (-not $__cmdletization_exceptionHasBeenThrown)
                          {
                              $__cmdletization_objectModelWrapper.EndProcessing()
                          }
                      }
                      catch
                      {
                          throw
                      }
                  }

                  # .EXTERNALHELP PS_ScheduledTask_v1.0.cdxml-Help.xml
              }
              Microsoft.PowerShell.Core\Export-ModuleMember -Function 'Stop-ScheduledTask' -Alias '*'



TimeCreated : 21/12/2025 23:03:19
Id          : 4104
ScriptText  : ameters]$__cmdletization_objectModelWrapper).GetDynamicParameters()
                              }
                          }
                      }
                      catch
                      {
                          $__cmdletization_exceptionHasBeenThrown = $true
                          throw
                      }
                  }

                  Begin {
                      $__cmdletization_exceptionHasBeenThrown = $false
                      try
                      {
                          __cmdletization_BindCommonParameters $__cmdletization_objectModelWrapper $PSBoundParameters
                          $__cmdletization_objectModelWrapper.BeginProcessing()
                      }
                      catch
                      {
                          $__cmdletization_exceptionHasBeenThrown = $true
                          throw
                      }
                  }


                  Process {
                      try
                      {
                          if (-not $__cmdletization_exceptionHasBeenThrown)
                          {
                    $__cmdletization_methodParameters = [System.Collections.Generic.List[Microsoft.PowerShell.Cmdletization.MethodParameter]]::new()

                    switch -exact ($PSCmdlet.ParameterSetName) {
                      { @('Object') -contains $_ } {
                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('InputObject')) {
                        [object]$__cmdletization_value = ${InputObject}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'InputObject'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'InputObject'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                    $__cmdletization_returnValue = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{ Name = 'ReturnValue'; ParameterType =
              'System.Int32'; Bindings = 'Error'; Value = $null; IsValuePresent = $false }
                    $__cmdletization_methodInvocationInfo = [Microsoft.PowerShell.Cmdletization.MethodInvocationInfo]::new('StartByObject',
              $__cmdletization_methodParameters, $__cmdletization_returnValue)
                    $__cmdletization_objectModelWrapper.ProcessRecord($__cmdletization_methodInvocationInfo)
                      }
                      { @('Path') -contains $_ } {
                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('TaskPath')) {
                        [object]$__cmdletization_value = ${TaskPath}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskPath'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskPath'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('TaskName')) {
                        [object]$__cmdletization_value = ${TaskName}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                    $__cmdletization_returnValue = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{ Name = 'ReturnValue'; ParameterType =
              'System.Int32'; Bindings = 'Error'; Value = $null; IsValuePresent = $false }
                    $__cmdletization_methodInvocationInfo = [Microsoft.PowerShell.Cmdletization.MethodInvocationInfo]::new('StartByPath',
              $__cmdletization_methodParameters, $__cmdletization_returnValue)
                    $__cmdletization_objectModelWrapper.ProcessRecord($__cmdletization_methodInvocationInfo)
                      }
                  }

                          }
                      }
                      catch
                      {
                          $__cmdletization_exceptionHasBeenThrown = $true
                          throw
                      }
                  }


                  End {
                      try
                      {
                          if (-not $__cmdletization_exceptionHasBeenThrown)
                          {
                              $__cmdletization_objectModelWrapper.EndProcessing()
                          }
                      }
                      catch
                      {
                          throw
                      }
                  }

                  # .EXTERNALHELP PS_ScheduledTask_v1.0.cdxml-Help.xml
              }
              Microsoft.PowerShell.Core\Export-ModuleMember -Function 'Start-ScheduledTask' -Alias '*'


              function Stop-ScheduledTask
              {
                  [CmdletBinding(DefaultParameterSetName='Path', PositionalBinding=$false)]


                  param(

                  [Parameter(ParameterSetName='Object', Mandatory=$true, Position=1, ValueFromPipeline=$true)]
                  [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask')]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [ciminstance]
                  ${InputObject},

                  [Parameter(ParameterSetName='Path', Position=1)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [string]
                  ${TaskPath},

                  [Parameter(ParameterSetName='Path', Mandatory=$true, Position=0)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [string]
                  ${TaskName},

                  [Parameter(ParameterSetName='Object')]
                  [Parameter(ParameterSetName='Path')]
                  [Alias('Session')]
                  [ValidateNotNullOrEmpty()]
                  [CimSession[]]
                  ${CimSession},

                  [Parameter(ParameterSetName='Object')]
                  [Parameter(ParameterSetName='Path')]
                  [int]
                  ${ThrottleLimit},

                  [Parameter(ParameterSetName='Object')]
                  [Parameter(ParameterSetName='Path')]
                  [switch]
                  ${AsJob})

                  DynamicParam {
                      try
                      {
                          if (-not $__cmdletization_exceptionHasBeenThrown)
                          {
                              $__cmdletization_objectModelWrapper = $script:ObjectModelWrapper::new()
                              $__cmdletization_objectModelWrapper.Initialize($PSCmdlet, $script:ClassName, $script:ClassVersion, $script:ModuleVersion,
              $script:PrivateData)

                              if ($__cmdletization_objectModelWrapper -is [System.Management.Automation.IDynamicParameters])
                              {
                                  ([System.Management.Automation.IDynamicParameters]$__cmdletization_objectModelWrapper).GetDynamicParameters()
                              }
                          }
                      }
                      catch
                      {
                          $__cmdletization_exceptionHasBeenThrown = $true
                          throw
                      }
                  }

                  Begin {
                      $__cmdletization_exceptionHasBeenThrown = $false
                      try
                      {
                          __cmdletization_BindCommonParameters $__cmdletization_objectModelWrapper $PSBoundParameters
                          $__cmdletization_objectModelWrapper.BeginProcessing()
                      }
                      catch
                      {
                          $__cmdletization_exceptionHasBeenThrown = $true
                          throw
                      }
                  }


                  Process {
                      try
                      {
                          if (-not $__cmdletization_exceptionHasBeenThrown)
                          {
                    $__cmdletization_methodParameters = [System.Collections.Generic.List[Microsoft.PowerShell.Cmdletization.MethodParameter]]::new()

                    switch -exact ($PSCmdlet.ParameterSetName) {
                      { @('Object') -contains $_ } {
                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('InputObject')) {
                        [object]$__cmdletization_value = ${InputObject}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'InputObject'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'InputObject'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                    $__cmdletization_returnValue = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{ Name = 'ReturnValue'; ParameterType =
              'System.Int32'; Bindings = 'Error'; Value = $null; IsValuePresent = $false }
                    $__cmdletization_methodInvocationInfo = [Microsoft.PowerShell.Cmdletization.MethodInvocationInfo]::new('StopByObject',
              $__cmdletization_methodParameters, $__cmdletization_returnValue)
                    $__cmdletization_objectModelWrapper.ProcessRecord($__cmdletization_methodInvocationInfo)
                      }
                      { @('Path') -contains $_ } {
                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('TaskPath')) {
                        [object]$__cmdletization_value = ${TaskPath}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskPath'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{N

TimeCreated : 21/12/2025 23:03:19
Id          : 4104
ScriptText  : Value = $null; IsValuePresent = $false }
                    $__cmdletization_methodInvocationInfo = [Microsoft.PowerShell.Cmdletization.MethodInvocationInfo]::new('SetByPrincipal',
              $__cmdletization_methodParameters, $__cmdletization_returnValue)
                    $__cmdletization_objectModelWrapper.ProcessRecord($__cmdletization_methodInvocationInfo)
                      }
                      { @('User') -contains $_ } {
                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Action')) {
                        [object]$__cmdletization_value = ${Action}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Action'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance[]'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Action'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance[]'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskAction'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('TaskPath')) {
                        [object]$__cmdletization_value = ${TaskPath}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskPath'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskPath'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Settings')) {
                        [object]$__cmdletization_value = ${Settings}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Settings'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Settings'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskSettings'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Trigger')) {
                        [object]$__cmdletization_value = ${Trigger}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Trigger'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance[]'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Trigger'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance[]'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskTrigger'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Password')) {
                        [object]$__cmdletization_value = ${Password}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Password'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Password'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('User')) {
                        [object]$__cmdletization_value = ${User}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'User'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'User'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('TaskName')) {
                        [object]$__cmdletization_value = ${TaskName}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'CmdletOutput'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'Out'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                    $__cmdletization_returnValue = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{ Name = 'ReturnValue'; ParameterType =
              'System.Int32'; Bindings = 'Error'; Value = $null; IsValuePresent = $false }
                    $__cmdletization_methodInvocationInfo = [Microsoft.PowerShell.Cmdletization.MethodInvocationInfo]::new('SetByUser',
              $__cmdletization_methodParameters, $__cmdletization_returnValue)
                    $__cmdletization_objectModelWrapper.ProcessRecord($__cmdletization_methodInvocationInfo)
                      }
                  }

                          }
                      }
                      catch
                      {
                          $__cmdletization_exceptionHasBeenThrown = $true
                          throw
                      }
                  }


                  End {
                      try
                      {
                          if (-not $__cmdletization_exceptionHasBeenThrown)
                          {
                              $__cmdletization_objectModelWrapper.EndProcessing()
                          }
                      }
                      catch
                      {
                          throw
                      }
                  }

                  # .EXTERNALHELP PS_ScheduledTask_v1.0.cdxml-Help.xml
              }
              Microsoft.PowerShell.Core\Export-ModuleMember -Function 'Set-ScheduledTask' -Alias '*'


              function Start-ScheduledTask
              {
                  [CmdletBinding(DefaultParameterSetName='Path', PositionalBinding=$false)]


                  param(

                  [Parameter(ParameterSetName='Object', Mandatory=$true, Position=1, ValueFromPipeline=$true)]
                  [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask')]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [ciminstance]
                  ${InputObject},

                  [Parameter(ParameterSetName='Path', Position=1)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [string]
                  ${TaskPath},

                  [Parameter(ParameterSetName='Path', Mandatory=$true, Position=0)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [string]
                  ${TaskName},

                  [Parameter(ParameterSetName='Object')]
                  [Parameter(ParameterSetName='Path')]
                  [Alias('Session')]
                  [ValidateNotNullOrEmpty()]
                  [CimSession[]]
                  ${CimSession},

                  [Parameter(ParameterSetName='Object')]
                  [Parameter(ParameterSetName='Path')]
                  [int]
                  ${ThrottleLimit},

                  [Parameter(ParameterSetName='Object')]
                  [Parameter(ParameterSetName='Path')]
                  [switch]
                  ${AsJob})

                  DynamicParam {
                      try
                      {
                          if (-not $__cmdletization_exceptionHasBeenThrown)
                          {
                              $__cmdletization_objectModelWrapper = $script:ObjectModelWrapper::new()
                              $__cmdletization_objectModelWrapper.Initialize($PSCmdlet, $script:ClassName, $script:ClassVersion, $script:ModuleVersion,
              $script:PrivateData)

                              if ($__cmdletization_objectModelWrapper -is [System.Management.Automation.IDynamicParameters])
                              {
                                  ([System.Management.Automation.IDynamicPar

TimeCreated : 21/12/2025 23:03:19
Id          : 4104
ScriptText  : nputObject}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'InputObject'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'InputObject'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Password')) {
                        [object]$__cmdletization_value = ${Password}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Password'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Password'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('User')) {
                        [object]$__cmdletization_value = ${User}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'User'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'User'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'CmdletOutput'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'Out'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                    $__cmdletization_returnValue = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{ Name = 'ReturnValue'; ParameterType =
              'System.Int32'; Bindings = 'Error'; Value = $null; IsValuePresent = $false }
                    $__cmdletization_methodInvocationInfo = [Microsoft.PowerShell.Cmdletization.MethodInvocationInfo]::new('SetByObject',
              $__cmdletization_methodParameters, $__cmdletization_returnValue)
                    $__cmdletization_objectModelWrapper.ProcessRecord($__cmdletization_methodInvocationInfo)
                      }
                      { @('Principal') -contains $_ } {
                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Principal')) {
                        [object]$__cmdletization_value = ${Principal}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Principal'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Principal'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskPrincipal'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Action')) {
                        [object]$__cmdletization_value = ${Action}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Action'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance[]'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Action'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance[]'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskAction'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('TaskPath')) {
                        [object]$__cmdletization_value = ${TaskPath}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskPath'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskPath'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Settings')) {
                        [object]$__cmdletization_value = ${Settings}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Settings'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Settings'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskSettings'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Trigger')) {
                        [object]$__cmdletization_value = ${Trigger}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Trigger'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance[]'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Trigger'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance[]'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskTrigger'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('TaskName')) {
                        [object]$__cmdletization_value = ${TaskName}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'CmdletOutput'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'Out'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                    $__cmdletization_returnValue = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{ Name = 'ReturnValue'; ParameterType =
              'System.Int32'; Bindings = 'Error';

TimeCreated : 21/12/2025 23:03:19
Id          : 4104
ScriptText  :         [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Password')) {
                        [object]$__cmdletization_value = ${Password}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Password'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Password'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('User')) {
                        [object]$__cmdletization_value = ${User}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'User'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'User'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('TaskPath')) {
                        [object]$__cmdletization_value = ${TaskPath}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskPath'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskPath'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('TaskName')) {
                        [object]$__cmdletization_value = ${TaskName}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'CmdletOutput'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'Out'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                    $__cmdletization_returnValue = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{ Name = 'ReturnValue'; ParameterType =
              'System.Int32'; Bindings = 'Error'; Value = $null; IsValuePresent = $false }
                    $__cmdletization_methodInvocationInfo = [Microsoft.PowerShell.Cmdletization.MethodInvocationInfo]::new('RegisterByXml',
              $__cmdletization_methodParameters, $__cmdletization_returnValue)
                    $__cmdletization_objectModelWrapper.ProcessRecord($__cmdletization_methodInvocationInfo)
                      }
                  }

                          }
                      }
                      catch
                      {
                          $__cmdletization_exceptionHasBeenThrown = $true
                          throw
                      }
                  }


                  End {
                      try
                      {
                          if (-not $__cmdletization_exceptionHasBeenThrown)
                          {
                              $__cmdletization_objectModelWrapper.EndProcessing()
                          }
                      }
                      catch
                      {
                          throw
                      }
                  }

                  # .EXTERNALHELP PS_ScheduledTask_v1.0.cdxml-Help.xml
              }
              Microsoft.PowerShell.Core\Export-ModuleMember -Function 'Register-ScheduledTask' -Alias '*'


              function Set-ScheduledTask
              {
                  [CmdletBinding(DefaultParameterSetName='User', PositionalBinding=$false)]

                  [OutputType([Microsoft.Management.Infrastructure.CimInstance])][OutputType('Microsoft.Management.Infrastructure.CimInstance#MSFT_Schedule
              dTask')][OutputType([Microsoft.Management.Infrastructure.CimInstance])][OutputType('Microsoft.Management.Infrastructure.CimInstance#MSFT_Sche
              duledTask')][OutputType([Microsoft.Management.Infrastructure.CimInstance])][OutputType('Microsoft.Management.Infrastructure.CimInstance#MSFT_
              ScheduledTask')]
                  param(

                  [Parameter(ParameterSetName='Object', Mandatory=$true, Position=0, ValueFromPipeline=$true)]
                  [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask')]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [ciminstance]
                  ${InputObject},

                  [Parameter(ParameterSetName='Object', Position=1)]
                  [Parameter(ParameterSetName='User', Position=6)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [string]
                  ${Password},

                  [Parameter(ParameterSetName='Object', Position=2)]
                  [Parameter(ParameterSetName='User', Position=5)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [string]
                  ${User},

                  [Parameter(ParameterSetName='Principal', Position=5)]
                  [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskPrincipal')]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [ciminstance]
                  ${Principal},

                  [Parameter(ParameterSetName='Principal', Position=2)]
                  [Parameter(ParameterSetName='User', Position=2)]
                  [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskAction')]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [ciminstance[]]
                  ${Action},

                  [Parameter(ParameterSetName='Principal', Position=1)]
                  [Parameter(ParameterSetName='User', Position=1)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [string]
                  ${TaskPath},

                  [Parameter(ParameterSetName='Principal', Position=4)]
                  [Parameter(ParameterSetName='User', Position=4)]
                  [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskSettings')]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [ciminstance]
                  ${Settings},

                  [Parameter(ParameterSetName='Principal', Position=3)]
                  [Parameter(ParameterSetName='User', Position=3)]
                  [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskTrigger')]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [ciminstance[]]
                  ${Trigger},

                  [Parameter(ParameterSetName='Principal', Mandatory=$true, Position=0)]
                  [Parameter(ParameterSetName='User', Mandatory=$true, Position=0)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [string]
                  ${TaskName},

                  [Parameter(ParameterSetName='Object')]
                  [Parameter(ParameterSetName='Principal')]
                  [Parameter(ParameterSetName='User')]
                  [Alias('Session')]
                  [ValidateNotNullOrEmpty()]
                  [CimSession[]]
                  ${CimSession},

                  [Parameter(ParameterSetName='Object')]
                  [Parameter(ParameterSetName='Principal')]
                  [Parameter(ParameterSetName='User')]
                  [int]
                  ${ThrottleLimit},

                  [Parameter(ParameterSetName='Object')]
                  [Parameter(ParameterSetName='Principal')]
                  [Parameter(ParameterSetName='User')]
                  [switch]
                  ${AsJob})

                  DynamicParam {
                      try
                      {
                          if (-not $__cmdletization_exceptionHasBeenThrown)
                          {
                              $__cmdletization_objectModelWrapper = $script:ObjectModelWrapper::new()
                              $__cmdletization_objectModelWrapper.Initialize($PSCmdlet, $script:ClassName, $script:ClassVersion, $script:ModuleVersion,
              $script:PrivateData)

                              if ($__cmdletization_objectModelWrapper -is [System.Management.Automation.IDynamicParameters])
                              {
                                  ([System.Management.Automation.IDynamicParameters]$__cmdletization_objectModelWrapper).GetDynamicParameters()
                              }
                          }
                      }
                      catch
                      {
                          $__cmdletization_exceptionHasBeenThrown = $true
                          throw
                      }
                  }

                  Begin {
                      $__cmdletization_exceptionHasBeenThrown = $false
                      try
                      {
                          __cmdletization_BindCommonParameters $__cmdletization_objectModelWrapper $PSBoundParameters
                          $__cmdletization_objectModelWrapper.BeginProcessing()
                      }
                      catch
                      {
                          $__cmdletization_exceptionHasBeenThrown = $true
                          throw
                      }
                  }


                  Process {
                      try
                      {
                          if (-not $__cmdletization_exceptionHasBeenThrown)
                          {
                    $__cmdletization_methodParameters = [System.Collections.Generic.List[Microsoft.PowerShell.Cmdletization.MethodParameter]]::new()

                    switch -exact ($PSCmdlet.ParameterSetName) {
                      { @('Object') -contains $_ } {
                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('InputObject')) {
                        [object]$__cmdletization_value = ${I

TimeCreated : 21/12/2025 23:03:19
Id          : 4104
ScriptText  : ect]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Trigger')) {
                        [object]$__cmdletization_value = ${Trigger}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Trigger'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance[]'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Trigger'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance[]'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskTrigger'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Settings')) {
                        [object]$__cmdletization_value = ${Settings}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Settings'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Settings'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskSettings'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Description')) {
                        [object]$__cmdletization_value = ${Description}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Description'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Description'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('User')) {
                        [object]$__cmdletization_value = ${User}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'User'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'User'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Password')) {
                        [object]$__cmdletization_value = ${Password}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Password'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Password'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Action')) {
                        [object]$__cmdletization_value = ${Action}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Action'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance[]'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Action'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance[]'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskAction'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('RunLevel')) {
                        [object]$__cmdletization_value = ${RunLevel}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'RunLevel'; ParameterType =
              'Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.RunLevelEnum'; Bindings = 'In'; Value = $__cmdletization_value;
              IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'RunLevel'; ParameterType =
              'Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.RunLevelEnum'; Bindings = 'In'; Value = $__cmdletization_defaultValue;
              IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('TaskName')) {
                        [object]$__cmdletization_value = ${TaskName}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'CmdletOutput'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'Out'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                    $__cmdletization_returnValue = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{ Name = 'ReturnValue'; ParameterType =
              'System.Int32'; Bindings = 'Error'; Value = $null; IsValuePresent = $false }
                    $__cmdletization_methodInvocationInfo = [Microsoft.PowerShell.Cmdletization.MethodInvocationInfo]::new('RegisterByUser',
              $__cmdletization_methodParameters, $__cmdletization_returnValue)
                    $__cmdletization_objectModelWrapper.ProcessRecord($__cmdletization_methodInvocationInfo)
                      }
                      { @('Xml') -contains $_ } {
                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Force')) {
                        [object]$__cmdletization_value = ${Force}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Force'; ParameterType =
              'System.Management.Automation.SwitchParameter'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Force'; ParameterType =
              'System.Management.Automation.SwitchParameter'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Xml')) {
                        [object]$__cmdletization_value = ${Xml}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Xml'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Xml'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)



TimeCreated : 21/12/2025 23:03:19
Id          : 4104
ScriptText  : ]$__cmdletization_value = ${Force}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Force'; ParameterType =
              'System.Management.Automation.SwitchParameter'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Force'; ParameterType =
              'System.Management.Automation.SwitchParameter'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Principal')) {
                        [object]$__cmdletization_value = ${Principal}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Principal'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Principal'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskPrincipal'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Action')) {
                        [object]$__cmdletization_value = ${Action}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Action'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance[]'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Action'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance[]'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskAction'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Description')) {
                        [object]$__cmdletization_value = ${Description}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Description'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Description'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('TaskPath')) {
                        [object]$__cmdletization_value = ${TaskPath}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskPath'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskPath'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Settings')) {
                        [object]$__cmdletization_value = ${Settings}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Settings'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Settings'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskSettings'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Trigger')) {
                        [object]$__cmdletization_value = ${Trigger}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Trigger'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance[]'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Trigger'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance[]'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskTrigger'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('TaskName')) {
                        [object]$__cmdletization_value = ${TaskName}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'CmdletOutput'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'Out'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                    $__cmdletization_returnValue = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{ Name = 'ReturnValue'; ParameterType =
              'System.Int32'; Bindings = 'Error'; Value = $null; IsValuePresent = $false }
                    $__cmdletization_methodInvocationInfo = [Microsoft.PowerShell.Cmdletization.MethodInvocationInfo]::new('RegisterByPrincipal',
              $__cmdletization_methodParameters, $__cmdletization_returnValue)
                    $__cmdletization_objectModelWrapper.ProcessRecord($__cmdletization_methodInvocationInfo)
                      }
                      { @('User') -contains $_ } {
                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Force')) {
                        [object]$__cmdletization_value = ${Force}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Force'; ParameterType =
              'System.Management.Automation.SwitchParameter'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Force'; ParameterType =
              'System.Management.Automation.SwitchParameter'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('TaskPath')) {
                        [object]$__cmdletization_value = ${TaskPath}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskPath'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskPath'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [obj

TimeCreated : 21/12/2025 23:03:19
Id          : 4104
ScriptText  : PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskAction')]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [ciminstance[]]
                  ${Action},

                  [Parameter(ParameterSetName='Principal', Position=6)]
                  [Parameter(ParameterSetName='User', Position=8)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [string]
                  ${Description},

                  [Parameter(ParameterSetName='Principal', Position=4)]
                  [Parameter(ParameterSetName='User', Position=4)]
                  [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskSettings')]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [ciminstance]
                  ${Settings},

                  [Parameter(ParameterSetName='Principal', Position=3)]
                  [Parameter(ParameterSetName='User', Position=3)]
                  [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskTrigger')]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [ciminstance[]]
                  ${Trigger},

                  [Parameter(ParameterSetName='User', Position=7)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.RunLevelEnum]
                  ${RunLevel},

                  [Parameter(ParameterSetName='Xml', Mandatory=$true, Position=2, ValueFromPipeline=$true)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [string]
                  ${Xml},

                  [Parameter(ParameterSetName='Object')]
                  [Parameter(ParameterSetName='Principal')]
                  [Parameter(ParameterSetName='User')]
                  [Parameter(ParameterSetName='Xml')]
                  [Alias('Session')]
                  [ValidateNotNullOrEmpty()]
                  [CimSession[]]
                  ${CimSession},

                  [Parameter(ParameterSetName='Object')]
                  [Parameter(ParameterSetName='Principal')]
                  [Parameter(ParameterSetName='User')]
                  [Parameter(ParameterSetName='Xml')]
                  [int]
                  ${ThrottleLimit},

                  [Parameter(ParameterSetName='Object')]
                  [Parameter(ParameterSetName='Principal')]
                  [Parameter(ParameterSetName='User')]
                  [Parameter(ParameterSetName='Xml')]
                  [switch]
                  ${AsJob})

                  DynamicParam {
                      try
                      {
                          if (-not $__cmdletization_exceptionHasBeenThrown)
                          {
                              $__cmdletization_objectModelWrapper = $script:ObjectModelWrapper::new()
                              $__cmdletization_objectModelWrapper.Initialize($PSCmdlet, $script:ClassName, $script:ClassVersion, $script:ModuleVersion,
              $script:PrivateData)

                              if ($__cmdletization_objectModelWrapper -is [System.Management.Automation.IDynamicParameters])
                              {
                                  ([System.Management.Automation.IDynamicParameters]$__cmdletization_objectModelWrapper).GetDynamicParameters()
                              }
                          }
                      }
                      catch
                      {
                          $__cmdletization_exceptionHasBeenThrown = $true
                          throw
                      }
                  }

                  Begin {
                      $__cmdletization_exceptionHasBeenThrown = $false
                      try
                      {
                          __cmdletization_BindCommonParameters $__cmdletization_objectModelWrapper $PSBoundParameters
                          $__cmdletization_objectModelWrapper.BeginProcessing()
                      }
                      catch
                      {
                          $__cmdletization_exceptionHasBeenThrown = $true
                          throw
                      }
                  }


                  Process {
                      try
                      {
                          if (-not $__cmdletization_exceptionHasBeenThrown)
                          {
                    $__cmdletization_methodParameters = [System.Collections.Generic.List[Microsoft.PowerShell.Cmdletization.MethodParameter]]::new()

                    switch -exact ($PSCmdlet.ParameterSetName) {
                      { @('Object') -contains $_ } {
                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Force')) {
                        [object]$__cmdletization_value = ${Force}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Force'; ParameterType =
              'System.Management.Automation.SwitchParameter'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Force'; ParameterType =
              'System.Management.Automation.SwitchParameter'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('InputObject')) {
                        [object]$__cmdletization_value = ${InputObject}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'InputObject'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'InputObject'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Password')) {
                        [object]$__cmdletization_value = ${Password}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Password'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Password'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('User')) {
                        [object]$__cmdletization_value = ${User}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'User'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'User'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('TaskName')) {
                        [object]$__cmdletization_value = ${TaskName}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskName'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('TaskPath')) {
                        [object]$__cmdletization_value = ${TaskPath}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskPath'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'TaskPath'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'CmdletOutput'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'Out'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                    $__cmdletization_returnValue = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{ Name = 'ReturnValue'; ParameterType =
              'System.Int32'; Bindings = 'Error'; Value = $null; IsValuePresent = $false }
                    $__cmdletization_methodInvocationInfo = [Microsoft.PowerShell.Cmdletization.MethodInvocationInfo]::new('RegisterByObject',
              $__cmdletization_methodParameters, $__cmdletization_returnValue)
                    $__cmdletization_objectModelWrapper.ProcessRecord($__cmdletization_methodInvocationInfo)
                      }
                      { @('Principal') -contains $_ } {
                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Force')) {
                        [object

TimeCreated : 21/12/2025 23:03:19
Id          : 4104
ScriptText  :  Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'CmdletOutput'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'Out'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskTrigger'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                    $__cmdletization_returnValue = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{ Name = 'ReturnValue'; ParameterType =
              'System.Int32'; Bindings = 'Error'; Value = $null; IsValuePresent = $false }
                    $__cmdletization_methodInvocationInfo = [Microsoft.PowerShell.Cmdletization.MethodInvocationInfo]::new('NewTriggerByStartup',
              $__cmdletization_methodParameters, $__cmdletization_returnValue)
                    $__cmdletization_objectModelWrapper.ProcessRecord($__cmdletization_methodInvocationInfo)
                      }
                      { @('Weekly') -contains $_ } {
                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('RandomDelay')) {
                        [object]$__cmdletization_value = ${RandomDelay}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'RandomDelay'; ParameterType =
              'System.TimeSpan'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'RandomDelay'; ParameterType =
              'System.TimeSpan'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('DaysOfWeek')) {
                        [object]$__cmdletization_value = ${DaysOfWeek}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'DaysOfWeek'; ParameterType =
              'System.DayOfWeek[]'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'DaysOfWeek'; ParameterType =
              'System.DayOfWeek[]'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Weekly')) {
                        [object]$__cmdletization_value = ${Weekly}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Weekly'; ParameterType =
              'System.Management.Automation.SwitchParameter'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Weekly'; ParameterType =
              'System.Management.Automation.SwitchParameter'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('WeeksInterval')) {
                        [object]$__cmdletization_value = ${WeeksInterval}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'WeeksInterval'; ParameterType =
              'System.UInt32'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'WeeksInterval'; ParameterType =
              'System.UInt32'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('At')) {
                        [object]$__cmdletization_value = ${At}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'At'; ParameterType =
              'System.DateTime'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'At'; ParameterType =
              'System.DateTime'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'CmdletOutput'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'Out'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskTrigger'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                    $__cmdletization_returnValue = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{ Name = 'ReturnValue'; ParameterType =
              'System.Int32'; Bindings = 'Error'; Value = $null; IsValuePresent = $false }
                    $__cmdletization_methodInvocationInfo = [Microsoft.PowerShell.Cmdletization.MethodInvocationInfo]::new('NewTriggerByWeekly',
              $__cmdletization_methodParameters, $__cmdletization_returnValue)
                    $__cmdletization_objectModelWrapper.ProcessRecord($__cmdletization_methodInvocationInfo)
                      }
                  }

                          }
                      }
                      catch
                      {
                          $__cmdletization_exceptionHasBeenThrown = $true
                          throw
                      }
                  }


                  End {
                      try
                      {
                          if (-not $__cmdletization_exceptionHasBeenThrown)
                          {
                              $__cmdletization_objectModelWrapper.EndProcessing()
                          }
                      }
                      catch
                      {
                          throw
                      }
                  }

                  # .EXTERNALHELP PS_ScheduledTask_v1.0.cdxml-Help.xml
              }
              Microsoft.PowerShell.Core\Export-ModuleMember -Function 'New-ScheduledTaskTrigger' -Alias '*'


              function Register-ScheduledTask
              {
                  [CmdletBinding(DefaultParameterSetName='User', PositionalBinding=$false)]

                  [OutputType([Microsoft.Management.Infrastructure.CimInstance])][OutputType('Microsoft.Management.Infrastructure.CimInstance#MSFT_Schedule
              dTask')][OutputType([Microsoft.Management.Infrastructure.CimInstance])][OutputType('Microsoft.Management.Infrastructure.CimInstance#MSFT_Sche
              duledTask')][OutputType([Microsoft.Management.Infrastructure.CimInstance])][OutputType('Microsoft.Management.Infrastructure.CimInstance#MSFT_
              ScheduledTask')][OutputType([Microsoft.Management.Infrastructure.CimInstance])][OutputType('Microsoft.Management.Infrastructure.CimInstance#M
              SFT_ScheduledTask')]
                  param(

                  [Parameter(ParameterSetName='Object')]
                  [Parameter(ParameterSetName='Principal')]
                  [Parameter(ParameterSetName='User')]
                  [Parameter(ParameterSetName='Xml')]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [switch]
                  ${Force},

                  [Parameter(ParameterSetName='Object', Mandatory=$true, Position=2, ValueFromPipeline=$true)]
                  [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask')]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [ciminstance]
                  ${InputObject},

                  [Parameter(ParameterSetName='Object', Position=4)]
                  [Parameter(ParameterSetName='User', Position=6)]
                  [Parameter(ParameterSetName='Xml', Position=4)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [string]
                  ${Password},

                  [Parameter(ParameterSetName='Object', Position=3)]
                  [Parameter(ParameterSetName='User', Position=5)]
                  [Parameter(ParameterSetName='Xml', Position=3)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [string]
                  ${User},

                  [Parameter(ParameterSetName='Object', Position=0)]
                  [Parameter(ParameterSetName='Principal', Mandatory=$true, Position=0)]
                  [Parameter(ParameterSetName='User', Mandatory=$true, Position=0)]
                  [Parameter(ParameterSetName='Xml', Mandatory=$true, Position=0)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [string]
                  ${TaskName},

                  [Parameter(ParameterSetName='Object', Position=1)]
                  [Parameter(ParameterSetName='Principal', Position=1)]
                  [Parameter(ParameterSetName='User', Position=1)]
                  [Parameter(ParameterSetName='Xml', Position=1)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [string]
                  ${TaskPath},

                  [Parameter(ParameterSetName='Principal', Position=5)]
                  [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskPrincipal')]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [ciminstance]
                  ${Principal},

                  [Parameter(ParameterSetName='Principal', Mandatory=$true, Position=2)]
                  [Parameter(ParameterSetName='User', Mandatory=$true, Position=2)]
                  [

TimeCreated : 21/12/2025 23:03:19
Id          : 4104
ScriptText  : arameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'RandomDelay'; ParameterType = 'System.TimeSpan'; Bindings = 'In';
              Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('AtLogOn')) {
                        [object]$__cmdletization_value = ${AtLogOn}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'AtLogOn'; ParameterType =
              'System.Management.Automation.SwitchParameter'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'AtLogOn'; ParameterType =
              'System.Management.Automation.SwitchParameter'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('User')) {
                        [object]$__cmdletization_value = ${User}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'User'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'User'; ParameterType =
              'System.String'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'CmdletOutput'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'Out'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskTrigger'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                    $__cmdletization_returnValue = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{ Name = 'ReturnValue'; ParameterType =
              'System.Int32'; Bindings = 'Error'; Value = $null; IsValuePresent = $false }
                    $__cmdletization_methodInvocationInfo = [Microsoft.PowerShell.Cmdletization.MethodInvocationInfo]::new('NewTriggerByLogon',
              $__cmdletization_methodParameters, $__cmdletization_returnValue)
                    $__cmdletization_objectModelWrapper.ProcessRecord($__cmdletization_methodInvocationInfo)
                      }
                      { @('Once') -contains $_ } {
                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('RandomDelay')) {
                        [object]$__cmdletization_value = ${RandomDelay}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'RandomDelay'; ParameterType =
              'System.TimeSpan'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'RandomDelay'; ParameterType =
              'System.TimeSpan'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('At')) {
                        [object]$__cmdletization_value = ${At}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'At'; ParameterType =
              'System.DateTime'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'At'; ParameterType =
              'System.DateTime'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Once')) {
                        [object]$__cmdletization_value = ${Once}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Once'; ParameterType =
              'System.Management.Automation.SwitchParameter'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Once'; ParameterType =
              'System.Management.Automation.SwitchParameter'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('RepetitionDuration')) {
                        [object]$__cmdletization_value = ${RepetitionDuration}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'RepetitionDuration';
              ParameterType = 'System.TimeSpan'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'RepetitionDuration';
              ParameterType = 'System.TimeSpan'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('RepetitionInterval')) {
                        [object]$__cmdletization_value = ${RepetitionInterval}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'RepetitionInterval';
              ParameterType = 'System.TimeSpan'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'RepetitionInterval';
              ParameterType = 'System.TimeSpan'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'CmdletOutput'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'Out'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskTrigger'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                    $__cmdletization_returnValue = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{ Name = 'ReturnValue'; ParameterType =
              'System.Int32'; Bindings = 'Error'; Value = $null; IsValuePresent = $false }
                    $__cmdletization_methodInvocationInfo = [Microsoft.PowerShell.Cmdletization.MethodInvocationInfo]::new('NewTriggerByOnce',
              $__cmdletization_methodParameters, $__cmdletization_returnValue)
                    $__cmdletization_objectModelWrapper.ProcessRecord($__cmdletization_methodInvocationInfo)
                      }
                      { @('Startup') -contains $_ } {
                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('RandomDelay')) {
                        [object]$__cmdletization_value = ${RandomDelay}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'RandomDelay'; ParameterType =
              'System.TimeSpan'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'RandomDelay'; ParameterType =
              'System.TimeSpan'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('AtStartup')) {
                        [object]$__cmdletization_value = ${AtStartup}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'AtStartup'; ParameterType =
              'System.Management.Automation.SwitchParameter'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'AtStartup'; ParameterType =
              'System.Management.Automation.SwitchParameter';

TimeCreated : 21/12/2025 23:03:19
Id          : 4104
ScriptText  : Instance])][OutputType('Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskTrigger')][OutputType([Microsoft.Management.Infrastructure.C
              imInstance])][OutputType('Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskTrigger')][OutputType([Microsoft.Management.Infrastructure
              .CimInstance])][OutputType('Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskTrigger')][OutputType([Microsoft.Management.Infrastructu
              re.CimInstance])][OutputType('Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskTrigger')]
                  param(

                  [Parameter(ParameterSetName='Daily', Mandatory=$true, Position=0)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [switch]
                  ${Daily},

                  [Parameter(ParameterSetName='Daily')]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [uint32]
                  ${DaysInterval},

                  [Parameter(ParameterSetName='Daily')]
                  [Parameter(ParameterSetName='Logon')]
                  [Parameter(ParameterSetName='Once')]
                  [Parameter(ParameterSetName='Startup')]
                  [Parameter(ParameterSetName='Weekly')]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [timespan]
                  ${RandomDelay},

                  [Parameter(ParameterSetName='Daily', Mandatory=$true)]
                  [Parameter(ParameterSetName='Once', Mandatory=$true)]
                  [Parameter(ParameterSetName='Weekly', Mandatory=$true)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [datetime]
                  ${At},

                  [Parameter(ParameterSetName='Logon', Mandatory=$true, Position=0)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [switch]
                  ${AtLogOn},

                  [Parameter(ParameterSetName='Logon')]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [string]
                  ${User},

                  [Parameter(ParameterSetName='Once', Mandatory=$true, Position=0)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [switch]
                  ${Once},

                  [Parameter(ParameterSetName='Once')]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [timespan]
                  ${RepetitionDuration},

                  [Parameter(ParameterSetName='Once')]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [timespan]
                  ${RepetitionInterval},

                  [Parameter(ParameterSetName='Startup', Mandatory=$true, Position=0)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [switch]
                  ${AtStartup},

                  [Parameter(ParameterSetName='Weekly')]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [System.DayOfWeek[]]
                  ${DaysOfWeek},

                  [Parameter(ParameterSetName='Weekly', Mandatory=$true, Position=0)]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [switch]
                  ${Weekly},

                  [Parameter(ParameterSetName='Weekly')]
                  [ValidateNotNull()]
                  [ValidateNotNullOrEmpty()]
                  [uint32]
                  ${WeeksInterval},

                  [Parameter(ParameterSetName='Daily')]
                  [Parameter(ParameterSetName='Logon')]
                  [Parameter(ParameterSetName='Once')]
                  [Parameter(ParameterSetName='Startup')]
                  [Parameter(ParameterSetName='Weekly')]
                  [Alias('Session')]
                  [ValidateNotNullOrEmpty()]
                  [CimSession[]]
                  ${CimSession},

                  [Parameter(ParameterSetName='Daily')]
                  [Parameter(ParameterSetName='Logon')]
                  [Parameter(ParameterSetName='Once')]
                  [Parameter(ParameterSetName='Startup')]
                  [Parameter(ParameterSetName='Weekly')]
                  [int]
                  ${ThrottleLimit},

                  [Parameter(ParameterSetName='Daily')]
                  [Parameter(ParameterSetName='Logon')]
                  [Parameter(ParameterSetName='Once')]
                  [Parameter(ParameterSetName='Startup')]
                  [Parameter(ParameterSetName='Weekly')]
                  [switch]
                  ${AsJob})

                  DynamicParam {
                      try
                      {
                          if (-not $__cmdletization_exceptionHasBeenThrown)
                          {
                              $__cmdletization_objectModelWrapper = $script:ObjectModelWrapper::new()
                              $__cmdletization_objectModelWrapper.Initialize($PSCmdlet, $script:ClassName, $script:ClassVersion, $script:ModuleVersion,
              $script:PrivateData)

                              if ($__cmdletization_objectModelWrapper -is [System.Management.Automation.IDynamicParameters])
                              {
                                  ([System.Management.Automation.IDynamicParameters]$__cmdletization_objectModelWrapper).GetDynamicParameters()
                              }
                          }
                      }
                      catch
                      {
                          $__cmdletization_exceptionHasBeenThrown = $true
                          throw
                      }
                  }

                  Begin {
                      $__cmdletization_exceptionHasBeenThrown = $false
                      try
                      {
                          __cmdletization_BindCommonParameters $__cmdletization_objectModelWrapper $PSBoundParameters
                          $__cmdletization_objectModelWrapper.BeginProcessing()
                      }
                      catch
                      {
                          $__cmdletization_exceptionHasBeenThrown = $true
                          throw
                      }
                  }


                  Process {
                      try
                      {
                          if (-not $__cmdletization_exceptionHasBeenThrown)
                          {
                    $__cmdletization_methodParameters = [System.Collections.Generic.List[Microsoft.PowerShell.Cmdletization.MethodParameter]]::new()

                    switch -exact ($PSCmdlet.ParameterSetName) {
                      { @('Daily') -contains $_ } {
                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Daily')) {
                        [object]$__cmdletization_value = ${Daily}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Daily'; ParameterType =
              'System.Management.Automation.SwitchParameter'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Daily'; ParameterType =
              'System.Management.Automation.SwitchParameter'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('DaysInterval')) {
                        [object]$__cmdletization_value = ${DaysInterval}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'DaysInterval'; ParameterType =
              'System.UInt32'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'DaysInterval'; ParameterType =
              'System.UInt32'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('RandomDelay')) {
                        [object]$__cmdletization_value = ${RandomDelay}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'RandomDelay'; ParameterType =
              'System.TimeSpan'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'RandomDelay'; ParameterType =
              'System.TimeSpan'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('At')) {
                        [object]$__cmdletization_value = ${At}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'At'; ParameterType =
              'System.DateTime'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'At'; ParameterType =
              'System.DateTime'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'CmdletOutput'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'Out'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskTrigger'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                    $__cmdletization_returnValue = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{ Name = 'ReturnValue'; ParameterType =
              'System.Int32'; Bindings = 'Error'; Value = $null; IsValuePresent = $false }
                    $__cmdletization_methodInvocationInfo = [Microsoft.PowerShell.Cmdletization.MethodInvocationInfo]::new('NewTriggerByDaily',
              $__cmdletization_methodParameters, $__cmdletization_returnValue)
                    $__cmdletization_objectModelWrapper.ProcessRecord($__cmdletization_methodInvocationInfo)
                      }
                      { @('Logon') -contains $_ } {
                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('RandomDelay')) {
                        [object]$__cmdletization_value = ${RandomDelay}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'RandomDelay'; ParameterType =
              'System.TimeSpan'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodP

TimeCreated : 21/12/2025 23:03:19
Id          : 4104
ScriptText  :  }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('IdleDuration')) {
                        [object]$__cmdletization_value = ${IdleDuration}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'IdleDuration'; ParameterType =
              'System.TimeSpan'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'IdleDuration'; ParameterType =
              'System.TimeSpan'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('RestartOnIdle')) {
                        [object]$__cmdletization_value = ${RestartOnIdle}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'RestartOnIdle'; ParameterType =
              'System.Management.Automation.SwitchParameter'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'RestartOnIdle'; ParameterType =
              'System.Management.Automation.SwitchParameter'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('DontStopOnIdleEnd')) {
                        [object]$__cmdletization_value = ${DontStopOnIdleEnd}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'DontStopOnIdleEnd'; ParameterType
              = 'System.Management.Automation.SwitchParameter'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'DontStopOnIdleEnd'; ParameterType
              = 'System.Management.Automation.SwitchParameter'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('ExecutionTimeLimit')) {
                        [object]$__cmdletization_value = ${ExecutionTimeLimit}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'ExecutionTimeLimit';
              ParameterType = 'System.TimeSpan'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'ExecutionTimeLimit';
              ParameterType = 'System.TimeSpan'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('MultipleInstances')) {
                        [object]$__cmdletization_value = ${MultipleInstances}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'MultipleInstances'; ParameterType
              = 'Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.MultipleInstancesEnum'; Bindings = 'In'; Value = $__cmdletization_value;
              IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'MultipleInstances'; ParameterType
              = 'Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.MultipleInstancesEnum'; Bindings = 'In'; Value =
              $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('Priority')) {
                        [object]$__cmdletization_value = ${Priority}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Priority'; ParameterType =
              'System.Int32'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'Priority'; ParameterType =
              'System.Int32'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('RestartCount')) {
                        [object]$__cmdletization_value = ${RestartCount}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'RestartCount'; ParameterType =
              'System.Int32'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'RestartCount'; ParameterType =
              'System.Int32'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('RestartInterval')) {
                        [object]$__cmdletization_value = ${RestartInterval}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'RestartInterval'; ParameterType =
              'System.TimeSpan'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'RestartInterval'; ParameterType =
              'System.TimeSpan'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent = $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                      if ($PSBoundParameters.ContainsKey('RunOnlyIfNetworkAvailable')) {
                        [object]$__cmdletization_value = ${RunOnlyIfNetworkAvailable}
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'RunOnlyIfNetworkAvailable';
              ParameterType = 'System.Management.Automation.SwitchParameter'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $true}
                      } else {
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'RunOnlyIfNetworkAvailable';
              ParameterType = 'System.Management.Automation.SwitchParameter'; Bindings = 'In'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      }
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                      [object]$__cmdletization_defaultValue = $null
                      [object]$__cmdletization_defaultValueIsPresent = $false
                        $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'CmdletOutput'; ParameterType =
              'Microsoft.Management.Infrastructure.CimInstance'; Bindings = 'Out'; Value = $__cmdletization_defaultValue; IsValuePresent =
              $__cmdletization_defaultValueIsPresent}
                      $__cmdletization_methodParameter.ParameterTypeName = 'Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskSettings'
                      $__cmdletization_methodParameters.Add($__cmdletization_methodParameter)

                    $__cmdletization_returnValue = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{ Name = 'ReturnValue'; ParameterType =
              'System.Int32'; Bindings = 'Error'; Value = $null; IsValuePresent = $false }
                    $__cmdletization_methodInvocationInfo = [Microsoft.PowerShell.Cmdletization.MethodInvocationInfo]::new('NewSettings',
              $__cmdletization_methodParameters, $__cmdletization_returnValue)
                    $__cmdletization_objectModelWrapper.ProcessRecord($__cmdletization_methodInvocationInfo)

                          }
                      }
                      catch
                      {
                          $__cmdletization_exceptionHasBeenThrown = $true
                          throw
                      }
                  }


                  End {
                      try
                      {
                          if (-not $__cmdletization_exceptionHasBeenThrown)
                          {
                              $__cmdletization_objectModelWrapper.EndProcessing()
                          }
                      }
                      catch
                      {
                          throw
                      }
                  }

                  # .EXTERNALHELP PS_ScheduledTask_v1.0.cdxml-Help.xml
              }
              Microsoft.PowerShell.Core\Export-ModuleMember -Function 'New-ScheduledTaskSettingsSet' -Alias '*'


              function New-ScheduledTaskTrigger
              {
                  [CmdletBinding(DefaultParameterSetName='Once', PositionalBinding=$false)]

                  [OutputType([Microsoft.Management.Infrastructure.CimInstance])][OutputType('Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskTrig
              ger')][OutputType([Microsoft.Management.Infrastructure.Cim

