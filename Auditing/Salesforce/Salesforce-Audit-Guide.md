# Salesforce Security Audit Guide

## Prerequisites
```bash
# Install Salesforce CLI
npm install -g @salesforce/cli

# Authenticate
sf org login web --alias production
```

## Key SOQL Queries

### Users
```sql
-- Active users with profiles
SELECT Id, Username, Profile.Name, IsActive, LastLoginDate 
FROM User WHERE IsActive = true

-- System Administrators
SELECT Id, Username FROM User 
WHERE Profile.Name = 'System Administrator' AND IsActive = true

-- Users not logged in for 90 days
SELECT Id, Username, LastLoginDate FROM User 
WHERE IsActive = true AND LastLoginDate < LAST_N_DAYS:90
```

### Permissions
```sql
-- Permission Sets with dangerous permissions
SELECT Id, Name, PermissionsModifyAllData, PermissionsViewAllData 
FROM PermissionSet WHERE PermissionsModifyAllData = true

-- Permission Set Assignments
SELECT Assignee.Username, PermissionSet.Name 
FROM PermissionSetAssignment
```

### Login History
```sql
-- Failed logins
SELECT LoginTime, UserId, Status, SourceIp 
FROM LoginHistory WHERE Status != 'Success' AND LoginTime = LAST_N_DAYS:7

-- Login by IP
SELECT SourceIp, COUNT(Id) FROM LoginHistory 
WHERE LoginTime = LAST_N_DAYS:30 GROUP BY SourceIp
```

### Security Settings (Setup)
Check manually in Setup:
- Session Settings (timeout, IP restrictions)
- Password Policies
- Login IP Ranges
- Certificate and Key Management
- Identity Provider settings

## SF CLI Commands
```bash
# Query data
sf data query --query "SELECT Id, Username FROM User" --target-org production

# Export users
sf data query --query "SELECT Id, Username, Profile.Name FROM User" --result-format csv > users.csv

# List permission sets
sf data query --query "SELECT Name, PermissionsModifyAllData FROM PermissionSet"
```

## Security Checklist
- [ ] MFA/SSO enabled
- [ ] Minimum System Admins
- [ ] No Modify All Data unless necessary
- [ ] Session timeout configured
- [ ] IP restrictions where possible
- [ ] Regular access reviews

## Resources
- [Salesforce Security Guide](https://help.salesforce.com/s/articleView?id=sf.security_overview.htm)
- [Health Check](https://help.salesforce.com/s/articleView?id=sf.security_health_check.htm)

---
*Version: 2.0.0 | Updated: 2025-01-26*
