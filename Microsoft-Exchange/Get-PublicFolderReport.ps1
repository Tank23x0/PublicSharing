<#
.SYNOPSIS
    Get-PublicFolderReport.ps1 - Public Folder Inventory and Analysis

.DESCRIPTION
    Generates comprehensive report of public folders including size,
    item count, permissions, and mail-enabled status.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.REQUIREMENTS
    - ExchangeOnlineManagement module
    - Exchange Administrator role

.EXAMPLE
    .\Get-PublicFolderReport.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Documents\PublicFolderReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludePermissions
)

#region ==================== CONFIGURATION ====================

$ScriptName = "Get-PublicFolderReport"
$ScriptVersion = "1.0.0"
$LogPath = "C:\Scripts\$ScriptName.log"

if (-not (Test-Path (Split-Path $LogPath))) {
    New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null
}

#endregion

#region ==================== FUNCTIONS ====================

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    Add-Content -Path $LogPath -Value $LogMessage -Force
    $Color = switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } }
    Write-Host $LogMessage -ForegroundColor $Color
}

function Show-Banner {
    $Banner = @"
╔══════════════════════════════════════════════════════════════════╗
║               PUBLIC FOLDER REPORT GENERATOR                     ║
║                      Version $ScriptVersion                              ║
╚══════════════════════════════════════════════════════════════════╝
"@
    Write-Host $Banner -ForegroundColor Cyan
}

#endregion

#region ==================== MAIN SCRIPT ====================

Show-Banner
Write-Log "========== Public Folder Report Started ==========" -Level "INFO"

# Module check
if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Write-Log "Installing ExchangeOnlineManagement module..." -Level "WARNING"
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

# Connect
Write-Log "Connecting to Exchange Online..." -Level "INFO"
Connect-ExchangeOnline -ShowBanner:$false

# Get public folders
Write-Log "Retrieving public folders..." -Level "INFO"

try {
    $PublicFolders = Get-PublicFolder -Recurse -ResultSize Unlimited
    $TotalFolders = $PublicFolders.Count
    Write-Log "Found $TotalFolders public folders" -Level "SUCCESS"
}
catch {
    Write-Log "Failed to retrieve public folders: $_" -Level "ERROR"
    Disconnect-ExchangeOnline -Confirm:$false
    exit 1
}

if ($TotalFolders -eq 0) {
    Write-Log "No public folders found" -Level "WARNING"
    Disconnect-ExchangeOnline -Confirm:$false
    exit 0
}

$Results = @()
$Counter = 0

foreach ($Folder in $PublicFolders) {
    $Counter++
    Write-Progress -Activity "Processing Public Folders" -Status "$($Folder.Name) ($Counter/$TotalFolders)" -PercentComplete (($Counter / $TotalFolders) * 100)
    
    try {
        # Get statistics
        $Stats = Get-PublicFolderStatistics -Identity $Folder.Identity -ErrorAction SilentlyContinue
        
        # Get mail-enabled status
        $MailEnabled = $null
        try {
            $MailEnabled = Get-MailPublicFolder -Identity $Folder.Identity -ErrorAction SilentlyContinue
        }
        catch {}
        
        # Get permissions if requested
        $Permissions = ""
        if ($IncludePermissions) {
            try {
                $FolderPerms = Get-PublicFolderClientPermission -Identity $Folder.Identity -ErrorAction SilentlyContinue
                $Permissions = ($FolderPerms | ForEach-Object { "$($_.User):$($_.AccessRights -join ',')" }) -join "; "
            }
            catch {}
        }
        
        $Results += [PSCustomObject]@{
            Name               = $Folder.Name
            FolderPath         = $Folder.FolderPath
            FolderType         = $Folder.FolderType
            ItemCount          = if ($Stats) { $Stats.ItemCount } else { "N/A" }
            TotalItemSizeKB    = if ($Stats) { [math]::Round($Stats.TotalItemSize.ToKB(), 2) } else { "N/A" }
            MailEnabled        = [bool]$MailEnabled
            EmailAddress       = if ($MailEnabled) { $MailEnabled.PrimarySmtpAddress } else { "" }
            HasSubfolders      = $Folder.HasSubfolders
            ParentPath         = $Folder.ParentPath
            ContentMailboxName = $Folder.ContentMailboxName
            Permissions        = $Permissions
        }
    }
    catch {
        Write-Log "Error on $($Folder.Name): $_" -Level "WARNING"
    }
}

Write-Progress -Activity "Processing Public Folders" -Completed

# Export
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# Statistics
$MailEnabledCount = ($Results | Where-Object { $_.MailEnabled -eq $true }).Count
$TotalItems = ($Results | Where-Object { $_.ItemCount -ne "N/A" } | Measure-Object -Property ItemCount -Sum).Sum
$TotalSizeKB = ($Results | Where-Object { $_.TotalItemSizeKB -ne "N/A" } | Measure-Object -Property TotalItemSizeKB -Sum).Sum

Disconnect-ExchangeOnline -Confirm:$false

# Summary
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Total Public Folders:  $TotalFolders" -ForegroundColor White
Write-Host "Mail-Enabled:          $MailEnabledCount" -ForegroundColor White
Write-Host "Total Items:           $TotalItems" -ForegroundColor White
Write-Host "Total Size:            $([math]::Round($TotalSizeKB / 1024, 2)) MB" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Log "========== Public Folder Report Completed ==========" -Level "SUCCESS"

#endregion
