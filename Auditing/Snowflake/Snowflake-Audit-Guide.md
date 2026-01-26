# Snowflake Security Audit Guide

## Prerequisites
- ACCOUNTADMIN or SECURITYADMIN role
- Access to SNOWFLAKE.ACCOUNT_USAGE schema

## Key Audit Areas

### User Audit
```sql
-- Stale users
SELECT name, last_success_login, 
    DATEDIFF('day', last_success_login, CURRENT_TIMESTAMP()) AS days_inactive
FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
WHERE disabled = 'false' 
    AND DATEDIFF('day', last_success_login, CURRENT_TIMESTAMP()) > 90;

-- Users without MFA
SELECT name FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
WHERE has_rsa_public_key = 'false' AND disabled = 'false';
```

### Role & Privileges
```sql
-- ACCOUNTADMIN users
SELECT grantee_name FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
WHERE role = 'ACCOUNTADMIN' AND deleted_on IS NULL;

-- Role grants
SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
WHERE deleted_on IS NULL;
```

### Login History
```sql
-- Failed logins
SELECT user_name, client_ip, error_message, event_timestamp
FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
WHERE is_success = 'NO' AND event_timestamp > DATEADD('day', -7, CURRENT_TIMESTAMP());
```

### Security Parameters
```sql
SHOW PARAMETERS LIKE '%PASSWORD%' IN ACCOUNT;
SHOW PARAMETERS LIKE '%SESSION%' IN ACCOUNT;
SHOW NETWORK POLICIES;
```

## Security Checklist
- [ ] Network policy configured
- [ ] MFA/SSO enabled
- [ ] Minimal ACCOUNTADMIN users
- [ ] Password policy enforced
- [ ] Session timeout configured
- [ ] Regular access reviews

## Resources
- [Snowflake Security Best Practices](https://docs.snowflake.com/en/user-guide/security-best-practices)
- [Access Control](https://docs.snowflake.com/en/user-guide/security-access-control-overview)

---
*Version: 2.0.0 | Updated: 2025-01-26*
