/*
===============================================================================
Snowflake Security Audit Queries
VERSION: 2.0.0
DATE: 2025-01-26

DESCRIPTION:
    Comprehensive security audit queries for Snowflake including:
    - User and role analysis
    - Access grants audit
    - Network policies
    - Account parameters
    - Login history
    - Query history

USAGE:
    Run these queries in Snowflake using ACCOUNTADMIN or SECURITYADMIN role
===============================================================================
*/

-- Set role for audit
USE ROLE ACCOUNTADMIN;

-- =============================================================================
-- USER AUDIT
-- =============================================================================

-- All users with key security attributes
SELECT 
    name AS username,
    login_name,
    created_on,
    last_success_login,
    disabled,
    locked_until_time,
    has_password,
    has_rsa_public_key,
    default_role,
    DATEDIFF('day', last_success_login, CURRENT_TIMESTAMP()) AS days_since_login
FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
WHERE deleted_on IS NULL
ORDER BY last_success_login DESC NULLS LAST;

-- Users who haven't logged in for 90+ days (stale accounts)
SELECT 
    name AS username,
    last_success_login,
    DATEDIFF('day', last_success_login, CURRENT_TIMESTAMP()) AS days_since_login
FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
WHERE deleted_on IS NULL
    AND disabled = 'false'
    AND (last_success_login IS NULL 
         OR DATEDIFF('day', last_success_login, CURRENT_TIMESTAMP()) > 90)
ORDER BY days_since_login DESC;

-- Users without MFA
SELECT name AS username, has_password, has_rsa_public_key
FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
WHERE deleted_on IS NULL
    AND disabled = 'false'
    AND has_rsa_public_key = 'false';

-- =============================================================================
-- ROLE AND PRIVILEGE AUDIT
-- =============================================================================

-- Role hierarchy
SELECT 
    grantee_name AS role,
    role AS granted_role
FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
WHERE granted_on = 'ROLE'
    AND privilege = 'USAGE'
    AND deleted_on IS NULL
ORDER BY grantee_name;

-- Users with ACCOUNTADMIN role
SELECT 
    grantee_name AS user_or_role,
    role AS admin_role,
    granted_by
FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
WHERE role = 'ACCOUNTADMIN'
    AND deleted_on IS NULL;

-- All account-level privileges
SELECT 
    grantee_name,
    privilege,
    granted_on,
    name AS object_name
FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
WHERE granted_on = 'ACCOUNT'
    AND deleted_on IS NULL
ORDER BY privilege;

-- Overly permissive grants (e.g., ALL PRIVILEGES)
SELECT 
    grantee_name,
    privilege,
    granted_on,
    name AS object_name
FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
WHERE privilege = 'ALL'
    AND deleted_on IS NULL;

-- =============================================================================
-- NETWORK POLICIES
-- =============================================================================

-- List network policies
SHOW NETWORK POLICIES;

-- Check if network policy is applied to account
SHOW PARAMETERS LIKE 'NETWORK_POLICY' IN ACCOUNT;

-- =============================================================================
-- ACCOUNT PARAMETERS (SECURITY SETTINGS)
-- =============================================================================

-- Key security parameters
SHOW PARAMETERS LIKE '%PASSWORD%' IN ACCOUNT;
SHOW PARAMETERS LIKE '%SESSION%' IN ACCOUNT;
SHOW PARAMETERS LIKE '%SSO%' IN ACCOUNT;
SHOW PARAMETERS LIKE '%MULTI_FACTOR%' IN ACCOUNT;

-- =============================================================================
-- LOGIN HISTORY
-- =============================================================================

-- Failed login attempts (last 7 days)
SELECT 
    user_name,
    client_ip,
    reported_client_type,
    error_code,
    error_message,
    event_timestamp
FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
WHERE is_success = 'NO'
    AND event_timestamp > DATEADD('day', -7, CURRENT_TIMESTAMP())
ORDER BY event_timestamp DESC;

-- Login count by user (last 30 days)
SELECT 
    user_name,
    COUNT(*) AS login_count,
    COUNT(CASE WHEN is_success = 'NO' THEN 1 END) AS failed_count
FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
WHERE event_timestamp > DATEADD('day', -30, CURRENT_TIMESTAMP())
GROUP BY user_name
ORDER BY failed_count DESC;

-- Logins from unusual locations
SELECT DISTINCT
    user_name,
    client_ip,
    reported_client_type
FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
WHERE event_timestamp > DATEADD('day', -30, CURRENT_TIMESTAMP())
    AND is_success = 'YES'
ORDER BY user_name;

-- =============================================================================
-- DATA ACCESS AUDIT
-- =============================================================================

-- Query history summary (data access patterns)
SELECT 
    user_name,
    role_name,
    COUNT(*) AS query_count,
    SUM(rows_produced) AS total_rows_produced
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE start_time > DATEADD('day', -7, CURRENT_TIMESTAMP())
GROUP BY user_name, role_name
ORDER BY query_count DESC;

-- Large data exports
SELECT 
    user_name,
    query_text,
    rows_produced,
    bytes_scanned
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE start_time > DATEADD('day', -7, CURRENT_TIMESTAMP())
    AND query_type = 'SELECT'
    AND rows_produced > 100000
ORDER BY rows_produced DESC
LIMIT 50;

-- =============================================================================
-- SHARING AND INTEGRATION AUDIT
-- =============================================================================

-- Outbound shares
SHOW SHARES;

-- Data sharing with external accounts
SELECT *
FROM SNOWFLAKE.ACCOUNT_USAGE.DATA_TRANSFER_HISTORY
WHERE transfer_type = 'DATA_SHARING'
    AND start_time > DATEADD('day', -30, CURRENT_TIMESTAMP());

-- Integrations
SHOW INTEGRATIONS;

-- =============================================================================
-- COMPLIANCE SUMMARY
-- =============================================================================

-- Summary findings query
SELECT 
    'Stale Users (90+ days)' AS check_name,
    COUNT(*) AS count
FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
WHERE deleted_on IS NULL
    AND disabled = 'false'
    AND (last_success_login IS NULL 
         OR DATEDIFF('day', last_success_login, CURRENT_TIMESTAMP()) > 90)
UNION ALL
SELECT 
    'ACCOUNTADMIN Users' AS check_name,
    COUNT(*) AS count
FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
WHERE role = 'ACCOUNTADMIN' AND deleted_on IS NULL
UNION ALL
SELECT 
    'Failed Logins (7 days)' AS check_name,
    COUNT(*) AS count
FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
WHERE is_success = 'NO'
    AND event_timestamp > DATEADD('day', -7, CURRENT_TIMESTAMP());
