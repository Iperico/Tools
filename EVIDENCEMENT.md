Windows PowerShell
Copyright (C) Microsoft Corporation. Tutti i diritti riservati.

Installa la versione più recente di PowerShell per nuove funzionalità e miglioramenti. https://aka.ms/PSWindows

PS C:\WINDOWS\system32> dsregcmd /status

+----------------------------------------------------------------------+
| Device State                                                         |
+----------------------------------------------------------------------+

             AzureAdJoined : NO
          EnterpriseJoined : NO
              DomainJoined : NO
           Virtual Desktop : NOT SET
               Device Name : Vagabondo

+----------------------------------------------------------------------+
| User State                                                           |
+----------------------------------------------------------------------+

                    NgcSet : NO
           WorkplaceJoined : YES
          WorkAccountCount : 1
             WamDefaultSet : NO

+----------------------------------------------------------------------+
| SSO State                                                            |
+----------------------------------------------------------------------+

                AzureAdPrt : NO
       AzureAdPrtAuthority : NO
             EnterprisePrt : NO
    EnterprisePrtAuthority : NO

+----------------------------------------------------------------------+
| Work Account 1                                                       |
+----------------------------------------------------------------------+

         WorkplaceDeviceId : a011becc-6f67-4413-831f-b8deeef8e2ff
       WorkplaceThumbprint : 0362FA97AE6EB079476FDFE7D55AEEF4A362D232
 DeviceCertificateValidity : [ 2021-12-07 15:28:54.000 UTC -- 2031-12-07 15:58:54.000 UTC ]
            KeyContainerId : 638b98ed-aed5-4e21-af90-718f0c8bddf8
               KeyProvider : Microsoft Platform Crypto Provider
              TpmProtected : YES
         WorkplaceTenantId : 028226e0-99ea-4fab-9d1b-daa440c9e286
       WorkplaceTenantName : Almaviva SpA
           WorkplaceMdmUrl :
      WorkplaceSettingsUrl :
                    NgcSet : NO

+----------------------------------------------------------------------+
| IE Proxy Config for Current User                                     |
+----------------------------------------------------------------------+

      Auto Detect Settings : NO
    Auto-Configuration URL :
         Proxy Server List :
         Proxy Bypass List :

+----------------------------------------------------------------------+
| WinHttp Default Proxy Config                                         |
+----------------------------------------------------------------------+

               Access Type : DIRECT

+----------------------------------------------------------------------+
| Ngc Prerequisite Check                                               |
+----------------------------------------------------------------------+

            IsDeviceJoined : NO
             IsUserAzureAD : NO
             PolicyEnabled : NO
          PostLogonEnabled : YES
            DeviceEligible : YES
        SessionIsNotRemote : YES
            CertEnrollment : none
              PreReqResult : WillNotProvision

For more information, please visit https://www.microsoft.com/aadjerrors