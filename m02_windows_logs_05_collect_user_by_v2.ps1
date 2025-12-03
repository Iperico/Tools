<#
.SYNOPSIS
  Raccolta forense user-centrica di Edge e log Windows con indice standardizzato.

.DESCRIPTION
  - Richiede CaseRef e uno o più utenti (UserRef) separati da virgole.
  - Chiede quanti giorni di log esportare (default 30).
  - Crea la cartella caso in C:\Forensic_Collect\<HOST>_<CaseRef>_<YYYYMMDD_HHMMSS>.
  - Per ogni utente crea una sottocartella User_<UserRef> con dump Edge e log.
  - Scrive EvidenceIndex.csv con la colonna UserRef valorizzata.

.NOTES
  - È pensato per esecuzione locale su host Windows con privilegi adeguati.
  - La colonna UserRef è coerente con la tabella EVIDENCE_INDEX del DB forense.
#>

param(
    [string]$OutputRoot = "C:\\Forensic_Collect"
)

Write-Host "=== Collect-User_By_v2 ===" -ForegroundColor Cyan
Write-Host "Host: $($env:COMPUTERNAME)" -ForegroundColor Cyan

# -----------------------------------------------------------------------------
# Input interattivi
# -----------------------------------------------------------------------------
$caseRef = Read-Host "Inserisci un nome riferimento/caso (es. INCIDENTE1)"
if ([string]::IsNullOrWhiteSpace($caseRef)) {
    $caseRef = "CASE"
}
$caseRefFolderSafe = ($caseRef -replace '[\\/:*?\"<>| ]','_')

$userInput = Read-Host "Inserisci uno o più utenti (separati da virgola, es. bob,alice)"
if ([string]::IsNullOrWhiteSpace($userInput)) {
    Write-Host "Nessun utente specificato, esco." -ForegroundColor Red
    return
}

$userRefs = $userInput.Split(",") |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -ne "" } |
    Select-Object -Unique

$daysInput = Read-Host "Quanti giorni indietro vuoi i log? [default 30]"
[int]$daysBack = 30
if (-not [string]::IsNullOrWhiteSpace($daysInput)) {
    if (-not [int]::TryParse($daysInput, [ref]$daysBack) -or $daysBack -le 0) {
        $daysBack = 30
    }
}

$now = Get-Date
$collectedOnUtc = $now.ToUniversalTime().ToString("o")
$startTime = $now.AddDays(-$daysBack)
$host = $env:COMPUTERNAME
$timestamp = $now.ToString("yyyyMMdd_HHmmss")
$caseFolderName = "{0}_{1}_{2}" -f $host, $caseRefFolderSafe, $timestamp
$caseFolder = Join-Path $OutputRoot $caseFolderName

Write-Host "Cartella caso: $caseFolder"
New-Item -Path $caseFolder -ItemType Directory -Force | Out-Null

$evidenceIndex = @()

function Add-Evidence {
    param(
        [string]$UserRef,
        [string]$SourceType,
        [string]$Description,
        [string]$RelativePath
    )

    $script:evidenceIndex += [pscustomobject]@{
        CaseRef      = $caseRef
        Host         = $host
        UserRef      = $UserRef
        CollectedOn  = $collectedOnUtc
        SourceType   = $SourceType
        Description  = $Description
        RelativePath = $RelativePath
    }
}

function Resolve-UserProfilePath {
    param([string]$UserRef)

    $candidate = Join-Path "C:\\Users" $UserRef
    if (Test-Path $candidate) { return $candidate }

    if ($UserRef -like "*\\*") {
        $short = $UserRef.Split("\\")[-1]
        $candidate2 = Join-Path "C:\\Users" $short
        if (Test-Path $candidate2) { return $candidate2 }
    }

    Write-Warning "Profilo utente non trovato per [$UserRef]"
    return $null
}

function Collect-EdgeForUser {
    param(
        [string]$UserRef,
        [string]$UserRootOut
    )

    $profilePath = Resolve-UserProfilePath -UserRef $UserRef
    if (-not $profilePath) { return }

    $edgeUserData = Join-Path $profilePath "AppData\\Local\\Microsoft\\Edge\\User Data"
    if (-not (Test-Path $edgeUserData)) {
        Write-Warning "Edge User Data non trovato per utente [$UserRef]: $edgeUserData"
        return
    }

    $edgeOut = Join-Path $UserRootOut "Edge"
    New-Item $edgeOut -ItemType Directory -Force | Out-Null

    Write-Host "  [EDGE] Utente $UserRef - User Data: $edgeUserData" -ForegroundColor Yellow

    Get-ChildItem -Path $edgeUserData -Directory | ForEach-Object {
        $profileName = $_.Name
        if ($profileName -eq "Default" -or $profileName -like "Profile *") {
            $srcProfilePath = $_.FullName
            $dstProfilePath = Join-Path $edgeOut $profileName
            New-Item $dstProfilePath -ItemType Directory -Force | Out-Null

            Write-Host "    -> Profilo Edge: $profileName"

            $files = @(
                "History",
                "History-journal",
                "Login Data",
                "Login Data-journal",
                "Web Data",
                "Cookies",
                "Bookmarks",
                "Preferences",
                "Favicons",
                "Top Sites"
            )

            foreach ($f in $files) {
                $src = Join-Path $srcProfilePath $f
                if (Test-Path $src) {
                    try {
                        $safeName = $f -replace ' ','_'
                        $dstFile  = "Edge_{0}_{1}" -f $safeName, $profileName
                        $dst      = Join-Path $dstProfilePath $dstFile
                        Copy-Item $src -Destination $dst -Force

                        $rel = $dst.Substring($caseFolder.Length + 1)
                        Add-Evidence -UserRef $UserRef `
                            -SourceType "Edge:Profile:$profileName" `
                            -Description "Copia file $f per utente $UserRef profilo $profileName" `
                            -RelativePath $rel
                    } catch {
                        Write-Warning "    Impossibile copiare $src : $_"
                    }
                }
            }
        }
    }
}

function Export-SecurityForUser {
    param(
        [string]$UserRef,
        [string]$LogsOut
    )

    New-Item $LogsOut -ItemType Directory -Force | Out-Null

    $outFile = Join-Path $LogsOut ("Security_{0}_last{1}d.evtx" -f ($UserRef -replace '[\\/:*?\"<>|]','_'), $daysBack)
    $startUtc = $startTime.ToUniversalTime().ToString("o")
    $xpath = @"
*[
  System[
    TimeCreated[@SystemTime>='$startUtc']
  ]
  and
  EventData[
    Data[@Name='TargetUserName']='$UserRef'
    or Data[@Name='SubjectUserName']='$UserRef'
  ]
]
"@

    try {
        wevtutil epl Security $outFile /q:"$xpath"
        $rel = $outFile.Substring($caseFolder.Length + 1)
        Add-Evidence -UserRef $UserRef `
            -SourceType "EventLog:Security" `
            -Description "Event log Security (ultimi $daysBack giorni) filtrato per utente $UserRef" `
            -RelativePath $rel
    } catch {
        Write-Warning "Errore esportando Security per $UserRef : $_"
    }
}

function Export-GenericLogsForUser {
    param(
        [string]$UserRef,
        [string]$LogsOut
    )

    $logs = @(
        @{ Name = "Microsoft-Windows-DNS-Client/Operational"; File = "DNSClient_last{0}d.evtx" -f $daysBack },
        @{ Name = "Microsoft-Windows-WLAN-AutoConfig/Operational"; File = "WLAN_last{0}d.evtx" -f $daysBack },
        @{ Name = "Application"; File = "Application_last{0}d.evtx" -f $daysBack },
        @{ Name = "System";      File = "System_last{0}d.evtx"      -f $daysBack }
    )

    foreach ($l in $logs) {
        $logName = $l.Name
        $fileName = $l.File
        $outPath = Join-Path $LogsOut $fileName

        try {
            $filter = @{ LogName = $logName; StartTime = $startTime; EndTime = $now }
            $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
            if ($events) {
                $startUtc = $startTime.ToUniversalTime().ToString("o")
                $xpath = "*[System[TimeCreated[@SystemTime>='$startUtc']]]"
                wevtutil epl $logName $outPath /q:"$xpath"

                $rel = $outPath.Substring($caseFolder.Length + 1)
                Add-Evidence -UserRef $UserRef `
                    -SourceType "EventLog:$logName" `
                    -Description "Event log $logName (ultimi $daysBack giorni) - associato a utente $UserRef" `
                    -RelativePath $rel
            }
        } catch {
            Write-Warning "Errore esportando log $logName : $_"
        }
    }
}

# -----------------------------------------------------------------------------
# Main loop sugli utenti
# -----------------------------------------------------------------------------
foreach ($u in $userRefs) {
    Write-Host "`n=== Utente: $u ===" -ForegroundColor Green

    $userFolder = Join-Path $caseFolder ("User_{0}" -f ($u -replace '[\\/:*?\"<>|]','_'))
    New-Item $userFolder -ItemType Directory -Force | Out-Null

    $logsOut = Join-Path $userFolder "EventLogs"

    Collect-EdgeForUser -UserRef $u -UserRootOut $userFolder
    Export-SecurityForUser -UserRef $u -LogsOut $logsOut
    Export-GenericLogsForUser -UserRef $u -LogsOut $logsOut
}

# -----------------------------------------------------------------------------
# EvidenceIndex.csv
# -----------------------------------------------------------------------------
$indexPath = Join-Path $caseFolder "EvidenceIndex.csv"
$evidenceIndex | Export-Csv -Path $indexPath -NoTypeInformation -Encoding UTF8

Write-Host "`nRaccolta completata."
Write-Host "Cartella caso: $caseFolder" -ForegroundColor Green
Write-Host "Indice evidenze: $indexPath" -ForegroundColor Green
