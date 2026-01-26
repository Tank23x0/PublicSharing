<#
.SYNOPSIS
    New-SharedMailbox.ps1 - Create New Shared Mailbox with Best Practices

.DESCRIPTION
    Creates a new shared mailbox with proper configuration including
    permissions, auto-mapping settings, and recommended security settings.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.REQUIREMENTS
    - ExchangeOnlineManagement module
    - Exchange Administrator role

.EXAMPLE
    .\New-SharedMailbox.ps1 -Name "IT Support" -Alias "itsupport" -Members "user1@domain.com","user2@domain.com"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Name,
    
    [Parameter(Mandatory = $true)]
    [string]$Alias,
    
    [Parameter(Mandatory = $false)]
    [string]$PrimarySmtpAddress,
    
    [Parameter(Mandatory = $false)]
    [string[]]$Members,
    
    [Parameter(Mandatory = $false)]
    [string[]]$Owners,
    
    [Parameter(Mandatory = $false)]
    [switch]$HideFromGAL,
    
    [Parameter(Mandatory = $false)]
    [switch]$DisableAutoMapping,
    
    [Parameter(Mandatory = $false)]
    [switch]$GrantSendAs
)

#region ==================== CONFIGURATION ====================

$ScriptName = "New-SharedMailbox"
$ScriptVersion = "1.0.0"
$LogPath = "C:\Scripts\$ScriptName.log"

if (-not (Test-Path (Split-Path $LogPath))) {
    New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null
}

#endregion

#region ==================== FUNCTIONS ====================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    Add-Content -Path $LogPath -Value $LogMessage -Force
    
    $Color = switch ($Level) {
        "INFO"    { "Cyan" }
        "WARNING" { "Yellow" }
        "ERROR"   { "Red" }
        "SUCCESS" { "Green" }
    }
    Write-Host $LogMessage -ForegroundColor $Color
}

function Show-Banner {
    $Banner = @"
╔══════════════════════════════════════════════════════════════════╗
║              NEW SHARED MAILBOX CREATOR                          ║
║                      Version $ScriptVersion                              ║
║                                                                  ║
║  Create shared mailboxes with best practice configuration        ║
╚══════════════════════════════════════════════════════════════════╝
"@
    Write-Host $Banner -ForegroundColor Cyan
}

function Test-ModuleInstalled {
    param([string]$ModuleName)
    return [bool](Get-Module -Name $ModuleName -ListAvailable)
}

function Install-RequiredModule {
    param([string]$ModuleName)
    
    if (-not (Test-ModuleInstalled -ModuleName $ModuleName)) {
        Write-Log "Module '$ModuleName' not found" -Level "WARNING"
        $Confirm = Read-Host "Install $ModuleName? (Y/N)"
        if ($Confirm -match '^[Yy]') {
            Install-Module -Name $ModuleName -Force -AllowClobber -Scope CurrentUser
            Write-Log "Module installed" -Level "SUCCESS"
        }
        else { exit 1 }
    }
}

#endregion

#region ==================== MAIN SCRIPT ====================

Show-Banner

Write-Log "========== Shared Mailbox Creation Started ==========" -Level "INFO"

# Module check
Install-RequiredModule -ModuleName "ExchangeOnlineManagement"
Import-Module ExchangeOnlineManagement -ErrorAction Stop

# Connect
Write-Log "Connecting to Exchange Online..." -Level "INFO"
try {
    Connect-ExchangeOnline -ShowBanner:$false
    Write-Log "Connected successfully" -Level "SUCCESS"
}
catch {
    Write-Log "Connection failed: $_" -Level "ERROR"
    exit 1
}

# Get domain for email address
if (-not $PrimarySmtpAddress) {
    $DefaultDomain = (Get-AcceptedDomain | Where-Object { $_.Default -eq $true }).DomainName
    $PrimarySmtpAddress = "$Alias@$DefaultDomain"
}

# Confirmation
Write-Host ""
Write-Host "Configuration Summary:" -ForegroundColor Yellow
Write-Host "  Display Name:      $Name" -ForegroundColor White
Write-Host "  Alias:             $Alias" -ForegroundColor White
Write-Host "  Email Address:     $PrimarySmtpAddress" -ForegroundColor White
Write-Host "  Members:           $(if ($Members) { $Members.Count } else { 0 })" -ForegroundColor White
Write-Host "  Hide from GAL:     $HideFromGAL" -ForegroundColor White
Write-Host "  Disable AutoMap:   $DisableAutoMapping" -ForegroundColor White
Write-Host "  Grant Send As:     $GrantSendAs" -ForegroundColor White
Write-Host ""
$Confirm = Read-Host "Create shared mailbox? (Y/N)"

if ($Confirm -notmatch '^[Yy]') {
    Write-Log "Creation cancelled" -Level "WARNING"
    Disconnect-ExchangeOnline -Confirm:$false
    exit 0
}

# Create shared mailbox
Write-Log "Creating shared mailbox: $Name" -Level "INFO"

try {
    $NewMailbox = New-Mailbox -Shared -Name $Name -Alias $Alias -PrimarySmtpAddress $PrimarySmtpAddress
    Write-Log "Shared mailbox created successfully" -Level "SUCCESS"
}
catch {
    Write-Log "Failed to create mailbox: $_" -Level "ERROR"
    Disconnect-ExchangeOnline -Confirm:$false
    exit 1
}

# Configure settings
if ($HideFromGAL) {
    Write-Log "Hiding mailbox from GAL..." -Level "INFO"
    Set-Mailbox -Identity $PrimarySmtpAddress -HiddenFromAddressListsEnabled $true
}

# Add members with Full Access
if ($Members) {
    $MemberCount = 0
    foreach ($Member in $Members) {
        Write-Log "Adding member: $Member" -Level "INFO"
        try {
            $AutoMapping = if ($DisableAutoMapping) { $false } else { $true }
            Add-MailboxPermission -Identity $PrimarySmtpAddress -User $Member -AccessRights FullAccess -AutoMapping:$AutoMapping -Confirm:$false
            
            if ($GrantSendAs) {
                Add-RecipientPermission -Identity $PrimarySmtpAddress -Trustee $Member -AccessRights SendAs -Confirm:$false
            }
            
            $MemberCount++
        }
        catch {
            Write-Log "Failed to add member $Member : $_" -Level "WARNING"
        }
    }
    Write-Log "Added $MemberCount members" -Level "SUCCESS"
}

# Add owners
if ($Owners) {
    foreach ($Owner in $Owners) {
        Write-Log "Adding owner: $Owner" -Level "INFO"
        try {
            Add-MailboxPermission -Identity $PrimarySmtpAddress -User $Owner -AccessRights FullAccess -AutoMapping:$true -Confirm:$false
            Add-RecipientPermission -Identity $PrimarySmtpAddress -Trustee $Owner -AccessRights SendAs -Confirm:$false
        }
        catch {
            Write-Log "Failed to add owner $Owner : $_" -Level "WARNING"
        }
    }
}

# Verify creation
$CreatedMailbox = Get-Mailbox -Identity $PrimarySmtpAddress

# Disconnect
Disconnect-ExchangeOnline -Confirm:$false

# Summary
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "              SHARED MAILBOX CREATION SUMMARY                  " -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Status:              SUCCESS" -ForegroundColor Green
Write-Host "Display Name:        $($CreatedMailbox.DisplayName)" -ForegroundColor White
Write-Host "Primary Email:       $($CreatedMailbox.PrimarySmtpAddress)" -ForegroundColor White
Write-Host "Alias:               $($CreatedMailbox.Alias)" -ForegroundColor White
Write-Host "Members Added:       $(if ($Members) { $MemberCount } else { 0 })" -ForegroundColor White
Write-Host ""
Write-Host "Log: $LogPath" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Log "========== Shared Mailbox Creation Completed ==========" -Level "SUCCESS"

#endregion
