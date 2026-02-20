<#
.SYNOPSIS
    New-DistributionList.ps1 - Create New Distribution List

.DESCRIPTION
    Creates a new distribution list with specified members and settings.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\New-DistributionList.ps1 -Name "Marketing Team" -Alias "marketing" -Members "user1@domain.com","user2@domain.com"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Name,
    
    [Parameter(Mandatory = $true)]
    [string]$Alias,
    
    [string]$PrimarySmtpAddress,
    [string[]]$Members,
    [string[]]$Owners,
    [switch]$RequireSenderAuth,
    [switch]$HideFromGAL,
    [switch]$ModeratedGroup
)

$ScriptName = "New-DistributionList"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              NEW DISTRIBUTION LIST CREATOR                       ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Creating Distribution List ==========" -Level "INFO"

if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

Connect-ExchangeOnline -ShowBanner:$false

# Get default domain if SMTP address not provided
if (-not $PrimarySmtpAddress) {
    $DefaultDomain = (Get-AcceptedDomain | Where-Object { $_.Default }).DomainName
    $PrimarySmtpAddress = "$Alias@$DefaultDomain"
}

Write-Host "`nCreating Distribution List:" -ForegroundColor Yellow
Write-Host "  Name:  $Name" -ForegroundColor White
Write-Host "  Email: $PrimarySmtpAddress" -ForegroundColor White
$Confirm = Read-Host "Continue? (Y/N)"

if ($Confirm -notmatch '^[Yy]') {
    Write-Log "Creation cancelled" -Level "WARNING"
    Disconnect-ExchangeOnline -Confirm:$false
    exit 0
}

try {
    $DLParams = @{
        Name = $Name
        Alias = $Alias
        PrimarySmtpAddress = $PrimarySmtpAddress
        RequireSenderAuthenticationEnabled = $RequireSenderAuth
    }
    
    if ($Owners) { $DLParams.ManagedBy = $Owners }
    
    $NewDL = New-DistributionGroup @DLParams
    Write-Log "Distribution list created: $PrimarySmtpAddress" -Level "SUCCESS"
    
    if ($HideFromGAL) {
        Set-DistributionGroup -Identity $PrimarySmtpAddress -HiddenFromAddressListsEnabled $true
    }
    
    if ($ModeratedGroup) {
        Set-DistributionGroup -Identity $PrimarySmtpAddress -ModerationEnabled $true
    }
    
    if ($Members) {
        foreach ($Member in $Members) {
            try {
                Add-DistributionGroupMember -Identity $PrimarySmtpAddress -Member $Member
                Write-Log "Added member: $Member" -Level "SUCCESS"
            }
            catch {
                Write-Log "Failed to add member $Member : $_" -Level "WARNING"
            }
        }
    }
}
catch {
    Write-Log "Failed to create distribution list: $_" -Level "ERROR"
    Disconnect-ExchangeOnline -Confirm:$false
    exit 1
}

Disconnect-ExchangeOnline -Confirm:$false

Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Distribution List Created: $PrimarySmtpAddress" -ForegroundColor Green
Write-Log "========== Creation Completed ==========" -Level "SUCCESS"
