# Zscaler Security Audit Guide

## API Authentication
```bash
# Generate API key in Zscaler Admin Portal
# Administration > API Key Management

# Base URLs by cloud:
# zscaler.net (Americas)
# zscalerone.net (Americas 2)
# zscalertwo.net (Europe)
# zscloud.net (APAC)
```

## Key Audit Areas

### Admin Users
- Review Super Admin count (minimize)
- Check for stale/disabled admins
- Verify MFA enabled

### URL Filtering
- Blocked categories configured
- Custom URL categories
- Allow list review

### Firewall Policies
- No overly permissive rules
- Proper segmentation
- Logging enabled

### SSL Inspection
- Appropriate bypasses only
- Certificate deployment
- Inspection categories

### DLP Policies
- Sensitive data dictionaries
- Enforcement actions
- Notification settings

## API Endpoints

| Resource | Endpoint |
|----------|----------|
| Auth | POST /api/v1/authenticatedSession |
| Admin Users | GET /api/v1/adminUsers |
| URL Policies | GET /api/v1/urlFilteringRules |
| Firewall Rules | GET /api/v1/firewallRules |
| DLP | GET /api/v1/dlpDictionaries |
| SSL Settings | GET /api/v1/sslSettings |
| Locations | GET /api/v1/locations |

## Security Checklist
- [ ] MFA for all admins
- [ ] Least privilege for admin roles
- [ ] URL filtering categories blocked
- [ ] SSL inspection enabled appropriately
- [ ] DLP policies for PII/sensitive data
- [ ] Audit logging enabled
- [ ] Regular policy review

## Resources
- [Zscaler API Documentation](https://help.zscaler.com/zia/api)
- [ZIA Best Practices](https://help.zscaler.com/zia/best-practices)
- [ZPA Security Guide](https://help.zscaler.com/zpa/zpa-help)

---
*Version: 2.0.0 | Updated: 2025-01-26*
