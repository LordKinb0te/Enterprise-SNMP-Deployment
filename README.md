# Enterprise SNMP Deployment Automation

Automated deployment of SNMP monitoring to Windows workstations using DCOM/WMI with fire-and-forget execution and local Features-on-Demand (FOD) caching.

## The Problem

Manual SNMP configuration across 100+ workstations in a hospitality environment would require:
- 2+ weeks of manual work
- Inconsistent configurations
- 4+ hours per machine with Windows Update-based FOD installation
- No existing enterprise deployment solution
- Multiple building locations requiring different configurations

## The Solution

PowerShell-based deployment system featuring:
- **Fire-and-forget execution**: Deploy to all machines in minutes, verify later
- **Dynamic location detection**: Automatically sets sysLocation based on hostname prefix
- **Local FOD caching**: Reduces installation time from 4 hours to 30 seconds
- **Zero-touch deployment**: No user interaction required
- **Encrypted credentials**: DPAPI-based secrets management
- **Idempotent**: Safe to run multiple times
- **LibreNMS integration**: Automatic monitoring device registration

## Architecture
```
┌─────────────────────┐
│ Deployment Station  │
│  (Your Workstation) │
└──────────┬──────────┘
           │ DCOM/SMB
           ▼
┌─────────────────────┐
│ Target Workstation  │
│   (100+ machines)   │
└──────────┬──────────┘
           │ Scheduled Task (SYSTEM)
           ▼
┌─────────────────────┐
│ Payload Execution   │
│  - Install SNMP     │
│  - Configure        │
│  - Enable Services  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ LibreNMS Monitoring │
│  (Auto-registered)  │
└─────────────────────┘
```

## Results

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Deployment Time | 2 weeks | 15 minutes | **99.3%** faster |
| Installation per Machine | 4+ hours | 30 seconds* | **99.8%** faster |
| Manual Configuration | Per-machine | Zero-touch | **100%** automated |
| Configuration Errors | Frequent | None | **100%** consistent |

*With local FOD caching. Falls back to Windows Update if unavailable.

## Quick Start

### 1. Setup
```powershell
# Create encrypted credentials
.\New-EncryptedSecret.ps1 -OutputPath .\secrets\snmp-community.enc

# Configure deployment (edit config.json)
{
  "SearchBase": "OU=Computers,DC=example,DC=local",
  "PermittedManagers": ["192.168.1.100"],
  "FireAndForget": true,
  "FODSourcePath": "\\\\server\\FODs\\SNMP"  # Optional
}
```

### 2. Deploy
```powershell
# Deploy to all workstations
.\SNMP_V2.ps1 -ConfigPath .\config-production.json

```

### 3. Register in Monitoring
```powershell
.\Add-LibreNMSDevice.ps1 `
    -DeploymentResultsCsv .\snmp_deployment_*.csv `
    -LibreNMSUrl "http://monitoring.example.com" `
    -ApiTokenPath .\secrets\librenms-api.enc
```

## Key Features

### Dynamic Location Detection
Automatically configures `sysLocation` based on hostname:
- `B-*` computers → "Beach"
- `P-*` computers → "Pointe"
- Others → Configurable default

### Fire-and-Forget Execution
Deployment script returns immediately; installations run asynchronously on remote machines. Check status later with verification script.

### Local FOD Caching
Copy SNMP Features-on-Demand to network share for instant installation. Automatically falls back to Windows Update if unavailable.

### Security
- Credentials encrypted with Windows DPAPI
- No credentials cached on remote machines
- Kerberos authentication (no password exposure)
- Deployment artifacts auto-cleaned
- WSUS settings restored after deployment

## Components

| File | Purpose |
|------|---------|
| `SNMP-Deployment-Refactored.ps1` | Main orchestration and deployment 

## Requirements

- PowerShell 7.2+
- Active Directory module
- Domain admin rights (or local admin on targets)
- SMB/DCOM connectivity to target machines

## Technical Details

**Execution Method**: DCOM/CIM for remote command execution (no WinRM required)  
**Authentication**: Kerberos delegation (credential-less)  
**Payload Delivery**: SMB admin shares  
**Async Pattern**: Scheduled tasks running as SYSTEM  
**Error Handling**: Comprehensive try/catch/finally with logging  
**Cleanup**: Automatic artifact removal post-deployment

## Real-World Context

Built for a hospitality infrastructure environment spanning two buildings with:
- 100+ Windows workstations
- Multiple physical locations
- Limited maintenance windows
- Zero tolerance for user disruption
- Need for centralized monitoring

## Lessons Learned

1. **Fire-and-forget pattern essential** for long-running remote operations
2. **Local FOD caching** dramatically improves deployment speed
3. **Idempotency** enables safe re-runs and reduces deployment anxiety
4. **Dynamic configuration** (hostname-based location) reduces manual work
5. **Comprehensive logging** on remote machines enables troubleshooting

## Future Enhancements

- [ ] Azure Key Vault integration for secrets
- [ ] Pester test coverage
- [ ] CI/CD pipeline integration
- [ ] Terraform module for infrastructure deployment
- [ ] Support for certificate-based SNMP v3

## Author

Built to solve real enterprise deployment challenges. Self-taught PowerShell and automation practices while managing production infrastructure.

## License

MIT
'@ | Out-File README.md -Encoding UTF8