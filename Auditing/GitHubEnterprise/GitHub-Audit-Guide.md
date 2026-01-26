# GitHub Enterprise Security Audit Guide

## Overview

Comprehensive guide for auditing GitHub Enterprise (Cloud and Server) including organization security, repository configurations, code security, and access management.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Organization Security](#organization-security)
3. [Member and Access Audit](#member-and-access-audit)
4. [Repository Security](#repository-security)
5. [Branch Protection](#branch-protection)
6. [Secret Scanning](#secret-scanning)
7. [Code Scanning](#code-scanning)
8. [GitHub Actions Security](#github-actions-security)
9. [Audit Log Review](#audit-log-review)
10. [API Reference](#api-reference)
11. [Compliance Mapping](#compliance-mapping)
12. [Resources](#resources)

---

## Prerequisites

### GitHub CLI

```bash
# Install
brew install gh  # macOS
winget install --id GitHub.cli  # Windows

# Authenticate
gh auth login

# Set organization scope
gh auth refresh -s admin:org,repo,audit_log
```

### Personal Access Token (Classic)

Required scopes:
- `admin:org` - Organization management
- `repo` - Repository access
- `audit_log` - Audit log access (Enterprise)
- `read:user` - User information
- `security_events` - Security alerts (GHAS)

### API Base URLs

| Platform | URL |
|----------|-----|
| GitHub.com | api.github.com |
| GitHub Enterprise Server | HOSTNAME/api/v3 |

---

## Organization Security

### GitHub CLI Commands

```bash
# View organization settings
gh api /orgs/ORG_NAME

# Check 2FA requirement
gh api /orgs/ORG_NAME --jq '.two_factor_requirement_enabled'

# Check default repository permissions
gh api /orgs/ORG_NAME --jq '.default_repository_permission'

# Check member privileges
gh api /orgs/ORG_NAME --jq '{
  members_can_create_repos: .members_can_create_repositories,
  members_can_create_public_repos: .members_can_create_public_repositories,
  members_can_create_private_repos: .members_can_create_private_repositories
}'
```

### Manual Steps (Console)

1. Navigate to **Organization Settings** → **Member privileges**
2. Review:
   - Base permissions (should be "No permission" or "Read")
   - Repository creation permissions
   - Forking permissions
   - Pages creation
3. Navigate to **Authentication security**
4. Verify 2FA requirement is enabled

### Security Checklist

- [ ] 2FA required for all members
- [ ] Default repository permission set to Read or None
- [ ] Public repository creation restricted
- [ ] Forking restricted (if needed)
- [ ] SAML SSO configured (Enterprise)
- [ ] IP allow list configured (Enterprise)

---

## Member and Access Audit

### GitHub CLI Commands

```bash
# List all organization members
gh api /orgs/ORG_NAME/members --paginate --jq '.[].login'

# List organization admins
gh api /orgs/ORG_NAME/members?role=admin --paginate --jq '.[].login'

# List members without 2FA (requires org admin)
gh api /orgs/ORG_NAME/members?filter=2fa_disabled --paginate --jq '.[].login'

# List outside collaborators
gh api /orgs/ORG_NAME/outside_collaborators --paginate --jq '.[] | {login, site_admin}'

# List pending invitations
gh api /orgs/ORG_NAME/invitations --jq '.[] | {login: .login, email: .email, role: .role}'

# Get member's organization role
gh api /orgs/ORG_NAME/memberships/USERNAME
```

### Team Audit

```bash
# List all teams
gh api /orgs/ORG_NAME/teams --paginate --jq '.[] | {name, privacy, permission}'

# List team members
gh api /orgs/ORG_NAME/teams/TEAM_SLUG/members --jq '.[].login'

# Get team repos
gh api /orgs/ORG_NAME/teams/TEAM_SLUG/repos --jq '.[] | {repo: .full_name, permission: .permissions}'
```

### Manual Steps

1. Navigate to **People** tab in organization
2. Filter by role (Admin, Member)
3. Check "2FA" column for compliance
4. Review "Last active" for stale accounts
5. Navigate to **Teams** and review memberships

---

## Repository Security

### GitHub CLI Commands

```bash
# List all repositories
gh repo list ORG_NAME --limit 1000 --json name,visibility,isArchived,pushedAt

# Find public repositories
gh repo list ORG_NAME --visibility public --json name,url

# Find repositories without branch protection
for repo in $(gh repo list ORG_NAME --json name -q '.[].name'); do
    protection=$(gh api /repos/ORG_NAME/$repo/branches/main/protection 2>/dev/null)
    if [ -z "$protection" ]; then
        echo "No protection: $repo"
    fi
done

# Get repository settings
gh api /repos/ORG_NAME/REPO_NAME --jq '{
    visibility: .visibility,
    default_branch: .default_branch,
    has_wiki: .has_wiki,
    has_pages: .has_pages,
    allow_forking: .allow_forking
}'

# List repository collaborators
gh api /repos/ORG_NAME/REPO_NAME/collaborators --jq '.[] | {login, permissions}'
```

### Repository Security Checklist

- [ ] Branch protection on default branch
- [ ] Require pull request reviews
- [ ] Require status checks
- [ ] No force pushes allowed
- [ ] No deletions allowed
- [ ] CODEOWNERS file present
- [ ] Dependency scanning enabled
- [ ] Secret scanning enabled

---

## Branch Protection

### GitHub CLI Commands

```bash
# Get branch protection rules
gh api /repos/ORG_NAME/REPO_NAME/branches/main/protection

# Check specific protections
gh api /repos/ORG_NAME/REPO_NAME/branches/main/protection --jq '{
    required_reviews: .required_pull_request_reviews.required_approving_review_count,
    dismiss_stale_reviews: .required_pull_request_reviews.dismiss_stale_reviews,
    require_code_owner_reviews: .required_pull_request_reviews.require_code_owner_reviews,
    required_status_checks: .required_status_checks.strict,
    enforce_admins: .enforce_admins.enabled,
    allow_force_pushes: .allow_force_pushes.enabled,
    allow_deletions: .allow_deletions.enabled
}'

# List branch protection rules (rulesets)
gh api /repos/ORG_NAME/REPO_NAME/rulesets
```

### Recommended Branch Protection Settings

| Setting | Recommendation | Description |
|---------|----------------|-------------|
| Require pull request | Yes | No direct pushes |
| Required approvals | 1-2 | Minimum reviewers |
| Dismiss stale reviews | Yes | Re-review after changes |
| Require code owner review | Yes | Owner must approve |
| Require status checks | Yes | CI must pass |
| Require up-to-date | Yes | Must be current with base |
| Require signed commits | Optional | Verify commit author |
| Allow force pushes | No | Prevent history rewrite |
| Allow deletions | No | Prevent branch deletion |

### Manual Steps

1. Navigate to repo → **Settings** → **Branches**
2. Click on branch protection rule
3. Review each protection setting
4. Verify "Include administrators" if applicable

---

## Secret Scanning

### GitHub CLI Commands

```bash
# List secret scanning alerts for org
gh api /orgs/ORG_NAME/secret-scanning/alerts --paginate --jq '.[] | {
    repo: .repository.full_name,
    secret_type: .secret_type,
    state: .state,
    created_at: .created_at
}'

# List open alerts only
gh api "/orgs/ORG_NAME/secret-scanning/alerts?state=open" --paginate

# Get alert details
gh api /repos/ORG_NAME/REPO_NAME/secret-scanning/alerts/ALERT_NUMBER

# List alerts for specific repo
gh api /repos/ORG_NAME/REPO_NAME/secret-scanning/alerts
```

### Manual Steps

1. Navigate to **Organization Security** → **Secret scanning alerts**
2. Review open alerts by severity
3. For each alert:
   - Identify the exposed secret type
   - Rotate the credential
   - Close the alert with resolution

### Secret Types Detected

- API keys (AWS, Azure, GCP, etc.)
- OAuth tokens
- SSH private keys
- Database connection strings
- Personal access tokens
- Slack webhooks
- And many more...

---

## Code Scanning

### GitHub CLI Commands

```bash
# List code scanning alerts for org
gh api /orgs/ORG_NAME/code-scanning/alerts --paginate --jq '.[] | {
    repo: .repository.full_name,
    rule: .rule.id,
    severity: .rule.severity,
    state: .state
}'

# Get critical/high alerts
gh api "/orgs/ORG_NAME/code-scanning/alerts?severity=critical,high&state=open" --paginate

# List alerts for specific repo
gh api /repos/ORG_NAME/REPO_NAME/code-scanning/alerts

# Get CodeQL analysis status
gh api /repos/ORG_NAME/REPO_NAME/code-scanning/analyses
```

### Setting Up CodeQL

```yaml
# .github/workflows/codeql.yml
name: "CodeQL"
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * 0'

jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
    - uses: actions/checkout@v4
    - uses: github/codeql-action/init@v3
      with:
        languages: javascript, python  # Adjust for your languages
    - uses: github/codeql-action/analyze@v3
```

---

## GitHub Actions Security

### GitHub CLI Commands

```bash
# Get Actions permissions for org
gh api /orgs/ORG_NAME/actions/permissions

# Get allowed actions policy
gh api /orgs/ORG_NAME/actions/permissions/selected-actions

# List organization secrets
gh api /orgs/ORG_NAME/actions/secrets --jq '.secrets[] | {name, visibility}'

# List organization variables
gh api /orgs/ORG_NAME/actions/variables --jq '.variables[] | {name, visibility}'

# Get self-hosted runners
gh api /orgs/ORG_NAME/actions/runners --jq '.runners[] | {name, status, os}'
```

### Actions Security Checklist

- [ ] Restrict Actions to verified creators
- [ ] Pin action versions (use SHA, not tags)
- [ ] Review workflow permissions
- [ ] Minimize GITHUB_TOKEN permissions
- [ ] Use OpenID Connect for cloud providers
- [ ] Secure self-hosted runners
- [ ] Review organization secrets access

### Secure Workflow Example

```yaml
name: Secure Build
on:
  pull_request:
    branches: [main]

permissions:
  contents: read  # Minimal permissions

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4  # Pin to version
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm ci
      - run: npm test
```

---

## Audit Log Review

### GitHub CLI Commands (Enterprise)

```bash
# Get audit log events
gh api /orgs/ORG_NAME/audit-log --paginate --jq '.[] | {
    action: .action,
    actor: .actor,
    created_at: .created_at,
    repo: .repo
}'

# Filter by action
gh api "/orgs/ORG_NAME/audit-log?phrase=action:repo.create" --paginate

# Filter by actor
gh api "/orgs/ORG_NAME/audit-log?phrase=actor:USERNAME" --paginate

# Get recent security events
gh api "/orgs/ORG_NAME/audit-log?phrase=action:org.update_member+action:repo.access" --paginate
```

### Key Events to Monitor

| Event | Description | Risk |
|-------|-------------|------|
| org.update_member | Role change | High |
| repo.create | New repository | Medium |
| repo.destroy | Repository deleted | High |
| team.add_member | Team membership | Medium |
| protected_branch.update | Branch protection change | High |
| org.disable_two_factor | 2FA disabled | Critical |
| repo.download_zip | Code downloaded | Low |
| secret_scanning_alert.create | Secret exposed | Critical |

---

## API Reference

### Key Endpoints

| Operation | Endpoint |
|-----------|----------|
| Get org | GET /orgs/{org} |
| List members | GET /orgs/{org}/members |
| List repos | GET /orgs/{org}/repos |
| Branch protection | GET /repos/{owner}/{repo}/branches/{branch}/protection |
| Secret alerts | GET /orgs/{org}/secret-scanning/alerts |
| Code scanning | GET /orgs/{org}/code-scanning/alerts |
| Audit log | GET /orgs/{org}/audit-log |
| Actions permissions | GET /orgs/{org}/actions/permissions |
| Teams | GET /orgs/{org}/teams |
| Webhooks | GET /orgs/{org}/hooks |

### API Headers

```bash
curl -H "Authorization: Bearer TOKEN" \
     -H "Accept: application/vnd.github+json" \
     -H "X-GitHub-Api-Version: 2022-11-28" \
     "https://api.github.com/orgs/ORG_NAME"
```

---

## Compliance Mapping

### SOC 2

| Control | GitHub Feature |
|---------|----------------|
| CC6.1 - Logical Access | Organization membership, SSO |
| CC6.2 - Access Authorization | Team permissions, CODEOWNERS |
| CC6.3 - Access Removal | Member removal, access reviews |
| CC8.1 - Change Management | Branch protection, PR reviews |

### ISO 27001

| Control | GitHub Feature |
|---------|----------------|
| A.9.2.3 - Privileged Access | Admin roles, team permissions |
| A.12.1.2 - Change Management | Branch protection, approvals |
| A.14.2.2 - System Change Control | PR reviews, status checks |

---

## Resources

### Official Documentation

- [GitHub Security Best Practices](https://docs.github.com/en/code-security)
- [GitHub Enterprise Security](https://docs.github.com/en/enterprise-cloud@latest/admin/overview/about-github-for-enterprises)
- [GitHub REST API](https://docs.github.com/en/rest)
- [GitHub CLI Manual](https://cli.github.com/manual/)

### Community Resources

- [GitHub Blog - Security](https://github.blog/category/security/)
- [GitHub Skills](https://skills.github.com/)

---

*Document Version: 2.0.0 | Last Updated: 2025-01-26*
