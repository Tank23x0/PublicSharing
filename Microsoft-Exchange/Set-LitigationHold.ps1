<#
.SYNOPSIS
    Set-LitigationHold.ps1 - Enable/Disable Litigation Hold

.DESCRIPTION
    Enables or disables litigation hold on mailboxes individually or in bulk.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Set-LitigationHold.ps1 -Mailbox user@domain.com -Enable
    
.EXAMPLE
    .\Set-LitigationHold.ps1 -CSVPath "C:\Users.csv" -Enable -HoldDuration 365
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Mailbox,
    
    [Parameter(Mandatory = $false)]
    [string]$CSVPath,
    
    [Parameter(Mandatory = $false)]
    [switch]$Enable,
    
    [Parameter(Mandatory = $false)]
    [switch]$Disable,
    
    [Parameter(Mandatory = $false)]
    [int]$HoldDuration,
    
    [Parameter(Mandatory = $false)]
    [string]$HoldOwner,
    
    [Parameter(Mandatory = $false)]
    [string]$HoldComment
)

$ScriptName = "Set-LitigationHold"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              LITIGATION HOLD MANAGEMENT TOOL                     ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Litigation Hold Management Started ==========" -Level "INFO"

# Validation
if (-not $Mailbox -and -not $CSVPath) {
    Write-Log "Please specify -Mailbox or -CSVPath" -Level "ERROR"
    exit 1
}

if (-not $Enable -and -not $Disable) {
    Write-Log "Please specify -Enable or -Disable" -Level "ERROR"
    exit 1
}

if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

Connect-ExchangeOnline -ShowBanner:$false

# Get target mailboxes
$Mailboxes = @()
if ($Mailbox) {
    $Mailboxes += $Mailbox
}
elseif ($CSVPath) {
    if (Test-Path $CSVPath) {
        $Mailboxes = (Import-Csv -Path $CSVPath).UserPrincipalName
        Write-Log "Loaded $($Mailboxes.Count) mailboxes from CSV" -Level "INFO"
    }
    else {
        Write-Log "CSV not found: $CSVPath" -Level "ERROR"
        exit 1
    }
}

# Confirmation
Write-Host "`nAction: $(if ($Enable) { 'ENABLE' } else { 'DISABLE' }) Litigation Hold" -ForegroundColor Yellow
Write-Host "Mailboxes: $($Mailboxes.Count)" -ForegroundColor Yellow
if ($HoldDuration) { Write-Host "Duration: $HoldDuration days" -ForegroundColor Yellow }

$Confirm = Read-Host "Continue? (Y/N)"
if ($Confirm -notmatch '^[Yy]') {
    Write-Log "Operation cancelled" -Level "WARNING"
    Disconnect-ExchangeOnline -Confirm:$false
    exit 0
}

$SuccessCount = 0
$FailCount = 0

foreach ($TargetMailbox in $Mailboxes) {
    try {
        $Params = @{ Identity = $TargetMailbox }
        
        if ($Enable) {
            $Params.LitigationHoldEnabled = $true
            if ($HoldDuration) { $Params.LitigationHoldDuration = $HoldDuration }
            if ($HoldOwner) { $Params.LitigationHoldOwner = $HoldOwner }
            if ($HoldComment) { $Params.LitigationHoldComment = $HoldComment }
        }
        else {
            $Params.LitigationHoldEnabled = $false
        }
        
        Set-Mailbox @Params
        Write-Log "$(if ($Enable) { 'Enabled' } else { 'Disabled' }) litigation hold: $TargetMailbox" -Level "SUCCESS"
        $SuccessCount++
    }
    catch {
        Write-Log "Failed: $TargetMailbox - $_" -Level "ERROR"
        $FailCount++
    }
}

Disconnect-ExchangeOnline -Confirm:$false

Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Successful: $SuccessCount" -ForegroundColor Green
Write-Host "Failed:     $FailCount" -ForegroundColor $(if ($FailCount -gt 0) { "Red" } else { "Green" })
Write-Log "========== Completed ==========" -Level "SUCCESS"
