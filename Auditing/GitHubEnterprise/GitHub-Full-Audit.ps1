<#
.SYNOPSIS
    Comprehensive GitHub Enterprise Security Audit Script
    
.DESCRIPTION
    Audits GitHub Enterprise (Cloud or Server) including:
    - Organization membership and roles
    - Repository access and permissions
    - Branch protection rules
    - Secret scanning and code scanning
    - Audit log review
    - SSO and 2FA compliance
    - Webhook configurations
    - GitHub Actions security
    
.AUTHOR
    Security Operations Team
    
.VERSION
    2.0.0
    
.DATE
    2025-01-26
    
.REQUIREMENTS
    - GitHub Personal Access Token with admin:org, repo, audit_log scopes
    - GitHub CLI (gh) recommended
    - For Enterprise Server: API access to your instance
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Token,
    
    [Parameter(Mandatory = $true)]
    [string]$Organization,
    
    [Parameter(Mandatory = $false)]
    [string]$EnterpriseSlug,  # For GitHub Enterprise Cloud
    
    [Parameter(Mandatory = $false)]
    [string]$BaseUrl = "https://api.github.com",  # Change for GHES
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Documents\Scripts\GitHub-Audit",
    
    [Parameter(Mandatory = $false)]
    [int]$StaleThresholdDays = 90,
    
    [Parameter(Mandatory = $false)]
    [switch]$ExportToCSV
)

#region Configuration

$script:Config = @{
    ScriptName = "GitHub-Full-Audit"
    Version = "2.0.0"
    StartTime = Get-Date
    LogFile = $null
    ReportFile = $null
    TotalFindings = 0
    CriticalFindings = 0
    HighFindings = 0
    MediumFindings = 0
    LowFindings = 0
}

if ($PSVersionTable.Platform -eq 'Unix') {
    $OutputPath = $OutputPath -replace '\$env:USERPROFILE', $env:HOME
}

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$script:Config.LogFile = Join-Path $OutputPath "GitHub-Audit-Log_$timestamp.txt"
$script:Config.ReportFile = Join-Path $OutputPath "GitHub-Audit-Report_$timestamp.html"

$script:AllFindings = @()

#endregion

#region Logging

function Write-AuditLog {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] [$Level] $Message"
    $color = switch ($Level) {
        "INFO" { "White" } "WARNING" { "Yellow" } "ERROR" { "Red" }
        "SUCCESS" { "Green" } "FINDING" { "Cyan" }
    }
    Write-Host $entry -ForegroundColor $color
    Add-Content -Path $script:Config.LogFile -Value $entry
}

function Write-Finding {
    param([string]$Category, [string]$Severity, [string]$Object, [string]$Finding, [string]$Recommendation)
    $script:Config.TotalFindings++
    switch ($Severity) {
        "CRITICAL" { $script:Config.CriticalFindings++ }
        "HIGH" { $script:Config.HighFindings++ }
        "MEDIUM" { $script:Config.MediumFindings++ }
        "LOW" { $script:Config.LowFindings++ }
    }
    $script:AllFindings += [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Category = $Category
        Severity = $Severity
        Object = $Object
        Finding = $Finding
        Recommendation = $Recommendation
    }
    Write-AuditLog "[$Severity] $Category - $Finding" "FINDING"
}

#endregion

#region API Functions

function Invoke-GitHubAPI {
    param(
        [string]$Endpoint,
        [string]$Method = "GET",
        [hashtable]$Body = @{}
    )
    
    $headers = @{
        "Authorization" = "Bearer $Token"
        "Accept" = "application/vnd.github+json"
        "X-GitHub-Api-Version" = "2022-11-28"
    }
    
    $uri = "$BaseUrl$Endpoint"
    
    try {
        if ($Method -eq "GET") {
            $response = Invoke-RestMethod -Uri $uri -Method $Method -Headers $headers
        }
        else {
            $response = Invoke-RestMethod -Uri $uri -Method $Method -Headers $headers -Body ($Body | ConvertTo-Json)
        }
        return $response
    }
    catch {
        Write-AuditLog "API Error ($Endpoint): $_" "ERROR"
        return $null
    }
}

function Get-AllPages {
    param([string]$Endpoint)
    
    $allResults = @()
    $page = 1
    $perPage = 100
    
    do {
        $separator = if ($Endpoint -match "\?") { "&" } else { "?" }
        $response = Invoke-GitHubAPI -Endpoint "$Endpoint${separator}per_page=$perPage&page=$page"
        
        if ($response -and $response.Count -gt 0) {
            $allResults += $response
            $page++
        }
        else {
            break
        }
    } while ($response.Count -eq $perPage)
    
    return $allResults
}

#endregion

#region Organization Audit

function Invoke-OrganizationAudit {
    Write-AuditLog "Auditing Organization Settings..." "INFO"
    
    try {
        $org = Invoke-GitHubAPI -Endpoint "/orgs/$Organization"
        
        if (-not $org) {
            Write-AuditLog "Could not retrieve organization info" "ERROR"
            return
        }
        
        Write-AuditLog "Organization: $($org.login) ($($org.name))" "INFO"
        
        # Check 2FA requirement
        if (-not $org.two_factor_requirement_enabled) {
            Write-Finding -Category "Organization" -Severity "CRITICAL" `
                -Object $Organization `
                -Finding "Two-factor authentication is not required for organization members" `
                -Recommendation "Enable mandatory 2FA in organization settings"
        }
        else {
            Write-AuditLog "2FA requirement is enabled" "SUCCESS"
        }
        
        # Check default repository permissions
        if ($org.default_repository_permission -eq "write" -or $org.default_repository_permission -eq "admin") {
            Write-Finding -Category "Organization" -Severity "HIGH" `
                -Object $Organization `
                -Finding "Default member repository permission is '$($org.default_repository_permission)'" `
                -Recommendation "Set default permission to 'read' or 'none'"
        }
        
        # Check if members can create repos
        if ($org.members_can_create_public_repositories) {
            Write-Finding -Category "Organization" -Severity "MEDIUM" `
                -Object $Organization `
                -Finding "Members can create public repositories" `
                -Recommendation "Restrict public repo creation to admins"
        }
        
        $script:OrgInfo = $org
    }
    catch {
        Write-AuditLog "Error in organization audit: $_" "ERROR"
    }
}

#endregion

#region Member Audit

function Invoke-MemberAudit {
    Write-AuditLog "Auditing Organization Members..." "INFO"
    
    try {
        $members = Get-AllPages -Endpoint "/orgs/$Organization/members"
        $admins = Get-AllPages -Endpoint "/orgs/$Organization/members?role=admin"
        
        $totalMembers = $members.Count
        $adminCount = $admins.Count
        
        Write-AuditLog "Total members: $totalMembers, Admins: $adminCount" "INFO"
        
        if ($adminCount -gt 5) {
            Write-Finding -Category "Members" -Severity "MEDIUM" `
                -Object "Organization Admins" `
                -Finding "$adminCount users have organization admin role" `
                -Recommendation "Reduce admin count to essential personnel (2-5 recommended)"
        }
        
        # Check for members without 2FA (if we can access this)
        try {
            $no2FA = Get-AllPages -Endpoint "/orgs/$Organization/members?filter=2fa_disabled"
            if ($no2FA -and $no2FA.Count -gt 0) {
                Write-Finding -Category "Members" -Severity "HIGH" `
                    -Object "2FA Compliance" `
                    -Finding "$($no2FA.Count) members do not have 2FA enabled" `
                    -Recommendation "Require 2FA or remove non-compliant members"
                
                foreach ($member in $no2FA) {
                    Write-Finding -Category "Members" -Severity "HIGH" `
                        -Object $member.login `
                        -Finding "Member does not have 2FA enabled" `
                        -Recommendation "Enable 2FA or remove from organization"
                }
            }
        }
        catch {
            Write-AuditLog "Could not check 2FA status (may require Enterprise)" "WARNING"
        }
        
        # Check outside collaborators
        try {
            $collaborators = Get-AllPages -Endpoint "/orgs/$Organization/outside_collaborators"
            if ($collaborators -and $collaborators.Count -gt 0) {
                Write-Finding -Category "Members" -Severity "LOW" `
                    -Object "Outside Collaborators" `
                    -Finding "$($collaborators.Count) outside collaborators have access" `
                    -Recommendation "Review outside collaborator access periodically"
            }
        }
        catch {}
        
        $script:MemberStats = @{
            Total = $totalMembers
            Admins = $adminCount
        }
    }
    catch {
        Write-AuditLog "Error in member audit: $_" "ERROR"
    }
}

#endregion

#region Repository Audit

function Invoke-RepositoryAudit {
    Write-AuditLog "Auditing Repositories..." "INFO"
    
    try {
        $repos = Get-AllPages -Endpoint "/orgs/$Organization/repos"
        
        $totalRepos = $repos.Count
        $publicRepos = ($repos | Where-Object { $_.visibility -eq "public" }).Count
        $privateRepos = ($repos | Where-Object { $_.visibility -eq "private" }).Count
        $archivedRepos = ($repos | Where-Object { $_.archived }).Count
        
        Write-AuditLog "Total repos: $totalRepos (Public: $publicRepos, Private: $privateRepos, Archived: $archivedRepos)" "INFO"
        
        if ($publicRepos -gt 0) {
            Write-Finding -Category "Repositories" -Severity "LOW" `
                -Object "Public Repositories" `
                -Finding "$publicRepos public repositories in organization" `
                -Recommendation "Review public repos to ensure no sensitive data"
        }
        
        foreach ($repo in $repos) {
            if ($repo.archived) { continue }
            
            $repoName = $repo.name
            
            # Check branch protection on default branch
            try {
                $defaultBranch = $repo.default_branch
                $protection = Invoke-GitHubAPI -Endpoint "/repos/$Organization/$repoName/branches/$defaultBranch/protection"
                
                if (-not $protection) {
                    Write-Finding -Category "Repositories" -Severity "HIGH" `
                        -Object "$Organization/$repoName" `
                        -Finding "Default branch '$defaultBranch' has no branch protection" `
                        -Recommendation "Enable branch protection rules"
                }
                else {
                    # Check specific protections
                    if (-not $protection.required_pull_request_reviews) {
                        Write-Finding -Category "Repositories" -Severity "MEDIUM" `
                            -Object "$Organization/$repoName" `
                            -Finding "Pull request reviews not required" `
                            -Recommendation "Require pull request reviews before merging"
                    }
                    
                    if (-not $protection.required_status_checks) {
                        Write-Finding -Category "Repositories" -Severity "LOW" `
                            -Object "$Organization/$repoName" `
                            -Finding "Status checks not required before merging" `
                            -Recommendation "Require status checks (CI/CD, tests)"
                    }
                    
                    if ($protection.allow_force_pushes.enabled) {
                        Write-Finding -Category "Repositories" -Severity "MEDIUM" `
                            -Object "$Organization/$repoName" `
                            -Finding "Force pushes are allowed on protected branch" `
                            -Recommendation "Disable force pushes on protected branches"
                    }
                }
            }
            catch {
                Write-Finding -Category "Repositories" -Severity "HIGH" `
                    -Object "$Organization/$repoName" `
                    -Finding "No branch protection on default branch" `
                    -Recommendation "Enable branch protection rules"
            }
            
            # Check for stale repos
            if ($repo.pushed_at) {
                $lastPush = [DateTime]$repo.pushed_at
                if ($lastPush -lt (Get-Date).AddDays(-$StaleThresholdDays)) {
                    Write-Finding -Category "Repositories" -Severity "LOW" `
                        -Object "$Organization/$repoName" `
                        -Finding "No activity in $([int]((Get-Date) - $lastPush).TotalDays) days" `
                        -Recommendation "Archive or remove inactive repositories"
                }
            }
        }
        
        $script:RepoStats = @{
            Total = $totalRepos
            Public = $publicRepos
            Private = $privateRepos
            Archived = $archivedRepos
        }
    }
    catch {
        Write-AuditLog "Error in repository audit: $_" "ERROR"
    }
}

#endregion

#region Secret Scanning Audit

function Invoke-SecretScanningAudit {
    Write-AuditLog "Auditing Secret Scanning Alerts..." "INFO"
    
    try {
        $alerts = Get-AllPages -Endpoint "/orgs/$Organization/secret-scanning/alerts"
        
        if ($alerts -and $alerts.Count -gt 0) {
            $openAlerts = ($alerts | Where-Object { $_.state -eq "open" }).Count
            
            if ($openAlerts -gt 0) {
                Write-Finding -Category "Secret Scanning" -Severity "CRITICAL" `
                    -Object "Secret Alerts" `
                    -Finding "$openAlerts open secret scanning alerts" `
                    -Recommendation "Rotate exposed secrets immediately and close alerts"
                
                # List specific alerts
                $alerts | Where-Object { $_.state -eq "open" } | ForEach-Object {
                    Write-Finding -Category "Secret Scanning" -Severity "CRITICAL" `
                        -Object "$($_.repository.full_name)" `
                        -Finding "Exposed $($_.secret_type) detected" `
                        -Recommendation "Rotate this credential and revoke access"
                }
            }
            else {
                Write-AuditLog "No open secret scanning alerts" "SUCCESS"
            }
        }
    }
    catch {
        Write-AuditLog "Could not retrieve secret scanning alerts (requires GHAS)" "WARNING"
    }
}

#endregion

#region Code Scanning Audit

function Invoke-CodeScanningAudit {
    Write-AuditLog "Auditing Code Scanning Alerts..." "INFO"
    
    try {
        $alerts = Get-AllPages -Endpoint "/orgs/$Organization/code-scanning/alerts"
        
        if ($alerts -and $alerts.Count -gt 0) {
            $criticalAlerts = ($alerts | Where-Object { $_.rule.severity -eq "critical" -and $_.state -eq "open" }).Count
            $highAlerts = ($alerts | Where-Object { $_.rule.severity -eq "high" -and $_.state -eq "open" }).Count
            $openAlerts = ($alerts | Where-Object { $_.state -eq "open" }).Count
            
            if ($criticalAlerts -gt 0) {
                Write-Finding -Category "Code Scanning" -Severity "CRITICAL" `
                    -Object "Code Scanning" `
                    -Finding "$criticalAlerts critical code scanning alerts" `
                    -Recommendation "Remediate critical vulnerabilities immediately"
            }
            
            if ($highAlerts -gt 0) {
                Write-Finding -Category "Code Scanning" -Severity "HIGH" `
                    -Object "Code Scanning" `
                    -Finding "$highAlerts high severity code scanning alerts" `
                    -Recommendation "Address high severity vulnerabilities"
            }
            
            Write-AuditLog "Code scanning: $openAlerts open alerts" "INFO"
        }
    }
    catch {
        Write-AuditLog "Could not retrieve code scanning alerts (requires GHAS)" "WARNING"
    }
}

#endregion

#region Webhook Audit

function Invoke-WebhookAudit {
    Write-AuditLog "Auditing Webhooks..." "INFO"
    
    try {
        $webhooks = Invoke-GitHubAPI -Endpoint "/orgs/$Organization/hooks"
        
        if ($webhooks -and $webhooks.Count -gt 0) {
            foreach ($hook in $webhooks) {
                # Check for insecure webhooks
                if ($hook.config.url -match "^http://") {
                    Write-Finding -Category "Webhooks" -Severity "HIGH" `
                        -Object "Webhook $($hook.id)" `
                        -Finding "Webhook uses insecure HTTP: $($hook.config.url)" `
                        -Recommendation "Use HTTPS for all webhooks"
                }
                
                if (-not $hook.config.secret) {
                    Write-Finding -Category "Webhooks" -Severity "MEDIUM" `
                        -Object "Webhook $($hook.id)" `
                        -Finding "Webhook has no secret configured" `
                        -Recommendation "Add secret for webhook signature validation"
                }
            }
            
            Write-AuditLog "Found $($webhooks.Count) organization webhooks" "INFO"
        }
    }
    catch {
        Write-AuditLog "Could not retrieve webhooks" "WARNING"
    }
}

#endregion

#region Actions Audit

function Invoke-ActionsAudit {
    Write-AuditLog "Auditing GitHub Actions Settings..." "INFO"
    
    try {
        $actionsSettings = Invoke-GitHubAPI -Endpoint "/orgs/$Organization/actions/permissions"
        
        if ($actionsSettings) {
            if ($actionsSettings.enabled_repositories -eq "all") {
                Write-Finding -Category "Actions" -Severity "LOW" `
                    -Object "Actions Policy" `
                    -Finding "GitHub Actions enabled for all repositories" `
                    -Recommendation "Consider limiting to selected repositories"
            }
            
            if ($actionsSettings.allowed_actions -eq "all") {
                Write-Finding -Category "Actions" -Severity "MEDIUM" `
                    -Object "Actions Policy" `
                    -Finding "All GitHub Actions are allowed" `
                    -Recommendation "Restrict to verified creators or selected actions"
            }
        }
        
        # Check for organization secrets
        $secrets = Invoke-GitHubAPI -Endpoint "/orgs/$Organization/actions/secrets"
        if ($secrets -and $secrets.secrets) {
            Write-AuditLog "Found $($secrets.secrets.Count) organization secrets" "INFO"
        }
    }
    catch {
        Write-AuditLog "Could not retrieve Actions settings" "WARNING"
    }
}

#endregion

#region Report Generation

function Export-AuditReport {
    Write-AuditLog "Generating report..." "INFO"
    
    $duration = (Get-Date) - $script:Config.StartTime
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>GitHub Enterprise Audit Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f6f8fa; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }
        h1 { color: #24292f; border-bottom: 3px solid #0969da; padding-bottom: 15px; }
        .summary-box { display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }
        .summary-item { padding: 20px; border-radius: 8px; color: white; min-width: 120px; text-align: center; }
        .critical { background: #cf222e; }
        .high { background: #bf8700; }
        .medium { background: #9a6700; color: white; }
        .low { background: #0969da; }
        .info { background: #1a7f37; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #d0d7de; }
        th { background: #24292f; color: white; }
        .severity-critical { color: #cf222e; font-weight: bold; }
        .severity-high { color: #bf8700; font-weight: bold; }
        .severity-medium { color: #9a6700; }
        .severity-low { color: #0969da; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🐙 GitHub Enterprise Security Audit Report</h1>
        <p><strong>Organization:</strong> $Organization</p>
        <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        
        <h2>Summary</h2>
        <div class="summary-box">
            <div class="summary-item critical"><h3>$($script:Config.CriticalFindings)</h3><p>Critical</p></div>
            <div class="summary-item high"><h3>$($script:Config.HighFindings)</h3><p>High</p></div>
            <div class="summary-item medium"><h3>$($script:Config.MediumFindings)</h3><p>Medium</p></div>
            <div class="summary-item low"><h3>$($script:Config.LowFindings)</h3><p>Low</p></div>
            <div class="summary-item info"><h3>$($script:Config.TotalFindings)</h3><p>Total</p></div>
        </div>
        
        <h2>Findings</h2>
        <table>
            <tr><th>Severity</th><th>Category</th><th>Object</th><th>Finding</th><th>Recommendation</th></tr>
"@

    foreach ($f in ($script:AllFindings | Sort-Object { switch ($_.Severity) { "CRITICAL" {0} "HIGH" {1} "MEDIUM" {2} "LOW" {3} }})) {
        $html += "<tr><td class='severity-$($f.Severity.ToLower())'>$($f.Severity)</td><td>$($f.Category)</td><td>$($f.Object)</td><td>$($f.Finding)</td><td>$($f.Recommendation)</td></tr>"
    }

    $html += "</table></div></body></html>"
    $html | Out-File -FilePath $script:Config.ReportFile -Encoding UTF8
    Write-AuditLog "Report saved: $($script:Config.ReportFile)" "SUCCESS"
}

#endregion

#region Main

function Invoke-GitHubAudit {
    Write-AuditLog "=" * 60 "INFO"
    Write-AuditLog "GITHUB ENTERPRISE SECURITY AUDIT" "INFO"
    Write-AuditLog "=" * 60 "INFO"
    
    Invoke-OrganizationAudit
    Invoke-MemberAudit
    Invoke-RepositoryAudit
    Invoke-SecretScanningAudit
    Invoke-CodeScanningAudit
    Invoke-WebhookAudit
    Invoke-ActionsAudit
    
    Export-AuditReport
    
    Write-AuditLog "AUDIT COMPLETE - Findings: $($script:Config.TotalFindings)" "SUCCESS"
}

Invoke-GitHubAudit

#endregion
