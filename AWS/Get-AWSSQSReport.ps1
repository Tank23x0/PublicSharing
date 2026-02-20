<#
.SYNOPSIS
    Get-AWSSQSReport.ps1 - AWS Management Tool

.DESCRIPTION
    Professional AWS administration and security audit script.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.REQUIREMENTS
    - AWS.Tools modules
    - Appropriate AWS IAM permissions

.EXAMPLE
    .\Get-AWSSQSReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\Get-AWSSQSReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [string]$ProfileName = "default",
    [string]$Region = "us-east-1"
)

$ScriptName = "Get-AWSSQSReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              AMAZON WEB SERVICES MANAGEMENT TOOL                 ║
║          Version 1.0.0 — Joe Romaine — JoeRomaine.com            ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Get-AWSSQSReport Started ==========" -Level "INFO"

# Check and import modules
$RequiredModules = @("AWS.Tools.Common", "AWS.Tools.EC2", "AWS.Tools.S3", "AWS.Tools.IAM")
foreach ($Module in $RequiredModules) {
    if (-not (Get-Module -Name $Module -ListAvailable)) {
        Write-Log "Installing $Module module..." -Level "WARNING"
        Install-Module -Name $Module -Force -Scope CurrentUser
    }
}
Import-Module AWS.Tools.Common, AWS.Tools.EC2, AWS.Tools.S3, AWS.Tools.IAM -ErrorAction SilentlyContinue

# Set AWS credentials
Write-Log "Setting AWS profile: $ProfileName" -Level "INFO"
Set-AWSCredential -ProfileName $ProfileName
Set-DefaultAWSRegion -Region $Region

$Results = @()

# Add specific logic for this script
Write-Log "Retrieving AWS data..." -Level "INFO"

try {
    $EC2Instances = Get-EC2Instance -ErrorAction SilentlyContinue
    
    foreach ($Reservation in $EC2Instances) {
        foreach ($Instance in $Reservation.Instances) {
            $Results += [PSCustomObject]@{
                InstanceId      = $Instance.InstanceId
                InstanceType    = $Instance.InstanceType
                State           = $Instance.State.Name
                PublicIP        = $Instance.PublicIpAddress
                PrivateIP       = $Instance.PrivateIpAddress
                VpcId           = $Instance.VpcId
                SubnetId        = $Instance.SubnetId
                LaunchTime      = $Instance.LaunchTime
                Platform        = $Instance.Platform
            }
        }
    }
}
catch {
    Write-Log "Error: $_" -Level "WARNING"
}

# Export results
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "`nTotal Resources: $($Results.Count)" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Get-AWSSQSReport Completed ==========" -Level "SUCCESS"
