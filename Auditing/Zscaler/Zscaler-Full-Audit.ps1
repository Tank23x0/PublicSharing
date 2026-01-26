<#
.SYNOPSIS
    Zscaler Security Audit Script
.DESCRIPTION
    Audits Zscaler ZIA/ZPA configuration including policies, users, and security settings.
.VERSION
    2.0.0
.NOTES
    Requires Zscaler API credentials
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$CloudName,  # e.g., zscaler.net, zscalerone.net
    [Parameter(Mandatory=$true)][string]$Username,
    [Parameter(Mandatory=$true)][string]$Password,
    [Parameter(Mandatory=$true)][string]$ApiKey,
    [string]$OutputPath = "$env:USERPROFILE\Documents\Scripts\Zscaler-Audit"
)

$script:AllFindings = @()
$script:Config = @{TotalFindings=0;CriticalFindings=0;HighFindings=0;MediumFindings=0;LowFindings=0}
$script:BaseUrl = "https://zsapi.$CloudName/api/v1"
$script:Cookie = $null

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$ReportFile = Join-Path $OutputPath "Zscaler-Audit-Report_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').html"

function Write-Finding { param([string]$Category, [string]$Severity, [string]$Object, [string]$Finding, [string]$Recommendation)
    $script:Config.TotalFindings++; switch ($Severity) { "CRITICAL" { $script:Config.CriticalFindings++ } "HIGH" { $script:Config.HighFindings++ } "MEDIUM" { $script:Config.MediumFindings++ } "LOW" { $script:Config.LowFindings++ } }
    $script:AllFindings += [PSCustomObject]@{Category=$Category;Severity=$Severity;Object=$Object;Finding=$Finding;Recommendation=$Recommendation}
    Write-Host "[$Severity] $Finding" -ForegroundColor $(switch($Severity){"CRITICAL"{"Red"}"HIGH"{"DarkYellow"}"MEDIUM"{"Yellow"}"LOW"{"Cyan"}})
}

function Get-ZscalerSession {
    Write-Host "Authenticating to Zscaler..." -ForegroundColor White
    
    # Generate obfuscated API key
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds().ToString()
    $n = $now[-6..-1] -join ''
    $r = ($n[0], $n[3], $n[5], $n[1], $n[4], $n[2]) -join ''
    $key = ""
    for ($i = 0; $i -lt $ApiKey.Length; $i++) {
        $key += [char]([int][char]$ApiKey[$i] + [int]$r[$i % 6])
    }
    
    $body = @{
        apiKey = $key
        username = $Username
        password = $Password
        timestamp = $now
    } | ConvertTo-Json
    
    try {
        $response = Invoke-RestMethod -Uri "$script:BaseUrl/authenticatedSession" -Method POST -Body $body -ContentType "application/json" -SessionVariable session
        $script:WebSession = $session
        return $true
    }
    catch {
        Write-Host "Authentication failed: $_" -ForegroundColor Red
        return $false
    }
}

function Invoke-ZscalerAPI {
    param([string]$Endpoint)
    try {
        $response = Invoke-RestMethod -Uri "$script:BaseUrl$Endpoint" -Method GET -WebSession $script:WebSession
        return $response
    }
    catch { return $null }
}

Write-Host "=== ZSCALER SECURITY AUDIT ===" -ForegroundColor Cyan

if (Get-ZscalerSession) {
    
    # Admin Users
    Write-Host "Auditing Admin Users..." -ForegroundColor White
    $admins = Invoke-ZscalerAPI "/adminUsers"
    if ($admins) {
        $superAdmins = $admins | Where-Object { $_.role.name -eq "Super Admin" }
        if ($superAdmins.Count -gt 3) {
            Write-Finding -Category "Admin Access" -Severity "MEDIUM" -Object "Super Admins" `
                -Finding "$($superAdmins.Count) Super Admin accounts" `
                -Recommendation "Limit Super Admin accounts"
        }
        
        $disabledAdmins = $admins | Where-Object { $_.disabled -eq $true }
        if ($disabledAdmins) {
            Write-Finding -Category "Admin Access" -Severity "LOW" -Object "Disabled Admins" `
                -Finding "$($disabledAdmins.Count) disabled admin accounts exist" `
                -Recommendation "Remove disabled admin accounts"
        }
    }
    
    # URL Filtering Policies
    Write-Host "Checking URL Filtering..." -ForegroundColor White
    $urlPolicies = Invoke-ZscalerAPI "/urlFilteringRules"
    if (-not $urlPolicies -or $urlPolicies.Count -lt 5) {
        Write-Finding -Category "URL Filtering" -Severity "MEDIUM" -Object "URL Policies" `
            -Finding "Minimal URL filtering rules configured" `
            -Recommendation "Review and enhance URL filtering policies"
    }
    
    # Firewall Policies
    Write-Host "Checking Firewall Rules..." -ForegroundColor White
    $fwRules = Invoke-ZscalerAPI "/firewallRules"
    $allowAllRules = $fwRules | Where-Object { $_.action -eq "ALLOW" -and $_.destAddresses -contains "*" }
    if ($allowAllRules) {
        Write-Finding -Category "Firewall" -Severity "HIGH" -Object "Firewall Rules" `
            -Finding "Rules allowing traffic to any destination found" `
            -Recommendation "Restrict firewall rules to specific destinations"
    }
    
    # DLP Policies
    Write-Host "Checking DLP Policies..." -ForegroundColor White
    $dlpPolicies = Invoke-ZscalerAPI "/dlpDictionaries"
    if (-not $dlpPolicies) {
        Write-Finding -Category "DLP" -Severity "MEDIUM" -Object "DLP" `
            -Finding "No custom DLP dictionaries configured" `
            -Recommendation "Configure DLP policies for sensitive data"
    }
    
    # SSL Inspection
    Write-Host "Checking SSL Inspection..." -ForegroundColor White
    $sslSettings = Invoke-ZscalerAPI "/sslSettings"
    # Check if SSL inspection is bypassed for sensitive categories
    
    # Logout
    try { Invoke-RestMethod -Uri "$script:BaseUrl/authenticatedSession" -Method DELETE -WebSession $script:WebSession } catch {}
}

# Generate Report
$html = @"
<!DOCTYPE html><html><head><title>Zscaler Audit</title>
<style>body{font-family:Arial;margin:40px;background:#f5f5f5}.container{max-width:1200px;margin:0 auto;background:white;padding:30px;border-radius:8px}h1{color:#0090c8}table{width:100%;border-collapse:collapse}th,td{padding:10px;text-align:left;border-bottom:1px solid #ddd}th{background:#0090c8;color:white}.critical{color:#d32f2f}.high{color:#f57c00}.medium{color:#fbc02d}.low{color:#1976d2}</style></head>
<body><div class="container"><h1>🔒 Zscaler Security Audit</h1>
<p>Cloud: $CloudName</p><p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
<table><tr><th>Severity</th><th>Category</th><th>Object</th><th>Finding</th><th>Recommendation</th></tr>
"@
foreach ($f in $script:AllFindings) { $html += "<tr><td class='$($f.Severity.ToLower())'>$($f.Severity)</td><td>$($f.Category)</td><td>$($f.Object)</td><td>$($f.Finding)</td><td>$($f.Recommendation)</td></tr>" }
$html += "</table></div></body></html>"
$html | Out-File $ReportFile -Encoding UTF8
Write-Host "Report: $ReportFile" -ForegroundColor Green
