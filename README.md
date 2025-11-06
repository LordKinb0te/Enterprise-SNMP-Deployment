# Enterprise SNMP Deployment Automation

Automated deployment of SNMP monitoring to Windows workstations using DCOM/WMI with comprehensive configuration and idempotent execution.

## Overview

PowerShell-based deployment system for configuring SNMP on Windows workstations for LibreNMS monitoring. Features zero-touch deployment, encrypted credential management, and comprehensive idempotency checks to ensure consistent configuration across all machines.

## Key Features

- **Zero-touch deployment**: Fully automated SNMP configuration across multiple workstations
- **Microsoft Online FoD**: Downloads Features-on-Demand directly from Microsoft Update (no local source required)
- **Comprehensive idempotency**: Verifies all registry keys match expected configuration before skipping
- **Encrypted credentials**: DPAPI-based secret management for SNMP community strings
- **Parallel execution**: Deploys to multiple machines simultaneously with configurable throttling
- **Detailed logging**: Per-machine logs and deployment reports for troubleshooting
- **LibreNMS ready**: Configures SNMP with proper settings for LibreNMS integration

## Architecture

```
┌─────────────────────┐
│ Deployment Station  │
│  (Your Workstation) │
│  - SNMP_V3.ps1      │
│  - Config JSON      │
│  - Encrypted Secret │
└──────────┬──────────┘
           │ DCOM/SMB
           ▼
┌─────────────────────┐
│ Target Workstation  │
│   (Domain Joined)    │
│  1. Payload Deploy  │
│  2. Scheduled Task  │
│  3. SNMP Install    │
│  4. Registry Config │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ LibreNMS Monitoring │
│  (192.168.123.99)   │
└─────────────────────┘
```

## Requirements

- **PowerShell 7.0+**
- **Active Directory module** (`Import-Module ActiveDirectory`)
- **Domain admin rights** (or local admin on target machines)
- **SMB/DCOM connectivity** to target machines
- **Internet access** on target machines (for Microsoft Update FoD download)

## Quick Start

### 1. Create Encrypted SNMP Community String

```powershell
.\New-EncryptedSecret.ps1 -OutputPath .\secrets\snmp-community.enc
```

This will:
- Prompt you securely for the SNMP community string
- Encrypt it using Windows DPAPI
- Save to `.\secrets\snmp-community.enc`
- Verify the encryption works

**Note**: The encrypted file can only be decrypted by the same user on the same machine. For production, consider migrating to Azure Key Vault or HashiCorp Vault.

### 2. Configure Deployment Settings

Create or edit `config-production-V2.json`:

```json
{
  "SearchBase": "OU=Computers,OU=MyBusiness,DC=wickinn,DC=local",
  "CommunityStringSecretName": "snmp-community-string",
  "CommunityPermission": 4,
  "PermittedManagers": [
    "192.168.123.99"
  ],
  "SysContact": "IT Department",
  "SysLocation": "Beach",
  "DeploymentTimeoutMinutes": 15,
  "SecretProvider": "File",
  "SecretPath": ".\\secrets\\snmp-community.enc",
  "ThrottleLimit": 20,
  "Comment": "Production config - downloads FoD from Microsoft online"
}
```

**Configuration Options**:
- `SearchBase`: Active Directory OU path to search for workstations
- `CommunityPermission`: `4` = Read Only, `8` = Read Write
- `PermittedManagers`: Array of IP addresses allowed to query SNMP (LibreNMS server)
- `SysContact`: Contact information for SNMP agent
- `SysLocation`: Default location (can be overridden by hostname prefix)
- `DeploymentTimeoutMinutes`: Maximum time to wait for each deployment (default: 15)
- `SecretPath`: Path to encrypted community string file
- `ThrottleLimit`: Number of parallel deployments (default: 20)

### 3. Deploy SNMP Configuration

```powershell
.\SNMP_V3.ps1 -ConfigPath .\config-production-V2.json
```

The script will:
1. Discover all enabled workstations in the specified OU (excluding servers)
2. Check connectivity (SMB/DCOM/IPv4)
3. Deploy payload to each machine via SMB admin share
4. Execute as SYSTEM via scheduled task
5. Install SNMP and WMI-SNMP Provider from Microsoft Update
6. Configure all registry keys and services
7. Generate deployment report CSV

### 4. Review Results

The script outputs:
- Real-time deployment status for each machine
- Summary statistics (success rate, skipped machines, failures)
- CSV export: `snmp_deployment_YYYYMMDD_HHMMSS.csv`

**Status Values**:
- `OK`: Successfully configured
- `SKIP`: Already configured correctly (idempotency check passed)
- `CHECK`: Deployment completed but needs verification
- `ERR`: Error occurred during deployment
- `UNREACHABLE`: Machine not reachable via SMB/DCOM/IPv4

## What Gets Configured

### SNMP Registry Settings

- **ValidCommunities**: SNMP community string with read-only (4) or read-write (8) permission
- **PermittedManagers**: IP addresses allowed to query SNMP (typically LibreNMS server)
- **RFC1156Agent**:
  - `sysContact`: Contact information
  - `sysLocation`: Location identifier
  - `sysServices`: DWORD value `0x41` (65 decimal) indicating supported services (Physical + App)

### Services

- **SNMP Service**: Set to Automatic startup, restarted after configuration
- **SNMP Trap Service**: Set to Automatic startup, restarted after configuration

### Firewall

- **SNMP Inbound Rule**: UDP port 161 from permitted managers
- **WMI Rules**: Enabled for direct WMI access if needed

### Windows Capabilities (FoD)

- **SNMP.Client**: Core SNMP functionality
- **WMI-SNMP-Provider.Client**: WMI to SNMP bridge for Windows-specific OIDs

## Idempotency

The script includes comprehensive idempotency checks that verify:

1. ✅ SNMP service is running
2. ✅ Community string matches expected value
3. ✅ All permitted managers match expected list
4. ✅ sysContact matches expected value
5. ✅ sysLocation matches expected value
6. ✅ sysServices equals `0x41`

If all checks pass, the script skips configuration with status `SKIP: Already configured`. If any check fails, it proceeds with full configuration.

**Safe to re-run**: The script can be executed multiple times on the same machines without causing issues.

## Troubleshooting

### Check Individual Machine Logs

On each target workstation, check:
- `C:\Windows\Temp\snmpcap.log` - Full transcript log
- `C:\Windows\Temp\snmpcap.ok` - Status markers (BEGIN/END)
- `C:\Windows\Temp\snmpcap.cap.txt` - Installed capabilities list

### Common Issues

**"SNMP service not present after FoD install"**
- FoD installation may have failed
- Check internet connectivity on target machine
- Verify Windows Update services are running
- Review `snmpcap.log` for detailed error messages

**"Registry keys not set"**
- Check if script timed out (increase `DeploymentTimeoutMinutes`)
- Verify SYSTEM account has registry write permissions
- Review error messages in `snmpcap.log`

**"Machine unreachable"**
- Verify SMB admin shares are accessible (`\\hostname\C$`)
- Check DCOM connectivity
- Verify firewall allows SMB/DCOM traffic
- Ensure machine is powered on and domain-joined

### Test SNMP Manually

```powershell
# From LibreNMS server or any machine with snmpwalk
snmpwalk -v2c -c <community-string> <hostname>
```

Expected output includes system information and Windows-specific OIDs if WMI-SNMP provider is working.

## Security Considerations

- **Encrypted Secrets**: Community strings are encrypted using Windows DPAPI
- **No Plaintext Storage**: Secrets are never stored in plaintext in config files
- **Kerberos Authentication**: Uses domain authentication (no password exposure)
- **Minimal Permissions**: Only required registry keys are modified
- **WSUS Restoration**: Temporarily bypasses WSUS for FoD installation, then restores settings
- **Cleanup**: Deployment artifacts remain on target machines (consider cleanup script)

**Note**: The community string is embedded in plaintext in the deployed script (`C:\Windows\Temp\snmpcap.ps1`). This is expected for SNMP v2c deployment. Consider SNMP v3 with certificates for enhanced security.

## File Structure

```
.
├── SNMP_V3.ps1                 # Main deployment script
├── New-EncryptedSecret.ps1      # Create encrypted community string
├── config-production-V2.json    # Production configuration
├── secrets/
│   └── snmp-community.enc      # Encrypted SNMP community string
├── snmp_deployment_*.csv        # Deployment results (generated)
└── README.md                    # This file
```

## Components

| File | Purpose |
|------|---------|
| `SNMP_V3.ps1` | Main deployment script - discovers workstations, deploys SNMP configuration |
| `New-EncryptedSecret.ps1` | Creates encrypted SNMP community string using Windows DPAPI |
| `config-production-V2.json` | Configuration file specifying OU, managers, timeouts, etc. |

## Technical Details

**Execution Method**: DCOM/CIM for remote command execution (no WinRM required)  
**Authentication**: Kerberos delegation (credential-less)  
**Payload Delivery**: SMB admin shares (`\\hostname\C$\Windows\Temp\`)  
**Async Pattern**: Scheduled tasks running as SYSTEM  
**Error Handling**: Comprehensive try/catch/finally with logging  
**FoD Source**: Microsoft Update (temporarily bypasses WSUS)  
**Timeout**: Configurable per-machine timeout (default: 15 minutes)

## Real-World Context

Built for enterprise deployment across multiple locations with:
- 100+ Windows workstations
- Multiple Active Directory OUs
- Limited maintenance windows
- Zero tolerance for user disruption
- Need for centralized monitoring via LibreNMS

## Future Enhancements

- [ ] Azure Key Vault integration for secrets
- [ ] HashiCorp Vault integration
- [ ] Automated cleanup of deployment artifacts
- [ ] SNMP v3 support with certificates
- [ ] Pester test coverage
- [ ] CI/CD pipeline integration
- [ ] Support for local FOD source path (faster deployments)

## License

MIT
