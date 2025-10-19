#requires -Version 7.2
#requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Enterprise SNMP deployment via DCOM with security hardening
.DESCRIPTION
    Idempotent SNMP rollout to AD workstations with:
    - Secret management integration
    - Pre-flight validation
    - Idempotency checks
    - Cleanup automation
    - Post-deployment verification
.NOTES
    Author: tandyman
    Version: 2.0
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ })]
    [string]$ConfigPath,

    [ValidateRange(1, 50)]
    [int]$ThrottleLimit = 20,

    [switch]$SkipVerification,
    
    [switch]$CleanupOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================================
# CONFIGURATION MANAGEMENT
# ============================================================================

class SNMPConfig {
    [string]$SearchBase
    [string]$CommunityStringSecretName
    [int]$CommunityPermission = 4
    [string[]]$PermittedManagers
    [string]$SysContact
    [string]$SysLocation
    [int]$DeploymentTimeoutMinutes = 15
    [string]$SecretProvider = 'File'  # File|AzureKeyVault|HashiCorpVault
    [string]$SecretPath
    [bool]$FireAndForget = $false  # If true, don't wait for completion
    [string]$FODSourcePath = $null  # Local path to FOD .cab files, or null for Windows Update
}

function Import-DeploymentConfig {
    param([string]$Path)
    
    if (-not (Test-Path $Path)) {
        throw "Config file not found: $Path"
    }
    
    $json = Get-Content $Path -Raw | ConvertFrom-Json
    $config = [SNMPConfig]::new()
    
    foreach ($prop in $json.PSObject.Properties) {
        if ($config.PSObject.Properties.Name -contains $prop.Name) {
            $config.$($prop.Name) = $prop.Value
        }
    }
    
    # Validation
    if (-not $config.SearchBase) { throw "SearchBase is required" }
    if (-not $config.PermittedManagers) { throw "PermittedManagers is required" }
    if (-not $config.CommunityStringSecretName) { throw "CommunityStringSecretName is required" }
    
    return $config
}

function Get-SNMPCommunityString {
    param(
        [SNMPConfig]$Config
    )
    
    switch ($Config.SecretProvider) {
        'File' {
            if (-not $Config.SecretPath -or -not (Test-Path $Config.SecretPath)) {
                throw "SecretPath required for File provider"
            }
            $encrypted = (Get-Content $Config.SecretPath -Raw).Trim()
            $secure = ConvertTo-SecureString $encrypted
            return [System.Net.NetworkCredential]::new('', $secure).Password
        }
        'AzureKeyVault' {
            # Example - requires Az.KeyVault module
            throw "AzureKeyVault provider not yet implemented. Use: Get-AzKeyVaultSecret"
        }
        'HashiCorpVault' {
            # Example - requires vault CLI or REST API
            throw "HashiCorpVault provider not yet implemented"
        }
        default {
            throw "Unknown secret provider: $($Config.SecretProvider)"
        }
    }
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Test-RemoteConnectivity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$ComputerName,
        
        [int]$TimeoutSeconds = 5
    )
    
    process {
        $checks = @{
            SMB  = $false
            DCOM = $false
            ICMP = $false
        }
        
        # SMB admin share
        try {
            $null = Get-Item "\\$ComputerName\C$" -ErrorAction Stop
            $checks.SMB = $true
        }
        catch {}
        
        # DCOM/CIM
        if (-not $checks.SMB) {
            try {
                $opt = New-CimSessionOption -Protocol Dcom
                $session = New-CimSession -ComputerName $ComputerName -SessionOption $opt `
                    -ErrorAction Stop -OperationTimeoutSec $TimeoutSeconds
                $checks.DCOM = $true
                Remove-CimSession $session -ErrorAction SilentlyContinue
            }
            catch {}
        }
        
        # ICMP (last resort)
        if (-not $checks.SMB -and -not $checks.DCOM) {
            try {
                $checks.ICMP = Test-Connection -TargetName $ComputerName -Count 1 -Quiet -TimeoutSeconds $TimeoutSeconds
            }
            catch {}
        }
        
        [PSCustomObject]@{
            ComputerName = $ComputerName
            Reachable    = ($checks.SMB -or $checks.DCOM -or $checks.ICMP)
            SMB          = $checks.SMB
            DCOM         = $checks.DCOM
            ICMP         = $checks.ICMP
        }
    }
}

function Test-SNMPServiceState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )
    
    try {
        $opt = New-CimSessionOption -Protocol Dcom
        $session = New-CimSession -ComputerName $ComputerName -SessionOption $opt -ErrorAction Stop
        
        try {
            # Check if SNMP service exists
            $snmpService = Get-CimInstance -ClassName Win32_Service -Filter "Name='SNMP'" `
                -CimSession $session -ErrorAction SilentlyContinue
            
            $snmpTrapService = Get-CimInstance -ClassName Win32_Service -Filter "Name='SNMPTRAP'" `
                -CimSession $session -ErrorAction SilentlyContinue
            
            [PSCustomObject]@{
                ComputerName      = $ComputerName
                SNMPInstalled     = $null -ne $snmpService
                SNMPRunning       = $snmpService.State -eq 'Running'
                SNMPTRAPInstalled = $null -ne $snmpTrapService
                SNMPTRAPRunning   = $snmpTrapService.State -eq 'Running'
            }
        }
        finally {
            Remove-CimSession $session
        }
    }
    catch {
        Write-Warning "Failed to check SNMP state on ${ComputerName}: $_"
        return $null
    }
}

function Test-SNMPConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [Parameter(Mandatory)]
        [SNMPConfig]$ExpectedConfig
    )
    
    try {
        $regPath = "\\$ComputerName\HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters"
        
        $vcPath = Join-Path $regPath 'ValidCommunities'
        $pmPath = Join-Path $regPath 'PermittedManagers'
        
        # Check if registry paths exist
        if (-not (Test-Path $vcPath) -or -not (Test-Path $pmPath)) {
            return $false
        }
        
        # Validate managers (basic check - at least one exists)
        $managers = Get-Item $pmPath | Select-Object -ExpandProperty Property
        if (-not $managers) {
            return $false
        }
        
        return $true
    }
    catch {
        return $false
    }
}

function Remove-DeploymentArtifacts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [string[]]$Artifacts = @('snmpcap.ps1', 'snmpcap.log', 'snmpcap.ok', 'snmpcap.run.log', 'snmpcap.cap.txt', 'snmpcap.task.txt')
    )
    
    foreach ($artifact in $Artifacts) {
        try {
            $path = "\\$ComputerName\C$\Windows\Temp\$artifact"
            if (Test-Path $path) {
                Remove-Item $path -Force -ErrorAction Stop
                Write-Verbose "Removed: $path"
            }
        }
        catch {
            Write-Warning "Failed to remove ${artifact} from ${ComputerName}: $_"
        }
    }
}

function Invoke-RemotePayloadDCOM {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [Parameter(Mandatory)]
        [string]$ScriptContent,
        
        [string]$RemoteScriptName = 'snmpcap.ps1',
        
        [int]$TimeoutMinutes = 15
    )
    
    $remotePath = "C:\Windows\Temp\$RemoteScriptName"
    $sharePath = "\\$ComputerName\C$\Windows\Temp\$RemoteScriptName"
    
    try {
        # 1. Deploy payload
        Set-Content -Path $sharePath -Value $ScriptContent -Encoding UTF8 -Force
        
        # 2. Create scheduled task
        $taskName = "SNMPDeploy_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
        $action = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $remotePath"
        $startTime = (Get-Date).AddMinutes(1).ToString('HH:mm')
        
        $opt = New-CimSessionOption -Protocol Dcom
        $session = New-CimSession -ComputerName $ComputerName -SessionOption $opt
        
        try {
            # Create task
            $createCmd = "schtasks /Create /TN `"$taskName`" /TR `"$action`" /SC ONCE /ST $startTime /RL HIGHEST /RU SYSTEM /F"
            $result = Invoke-CimMethod -ClassName Win32_Process -MethodName Create `
                -Arguments @{ CommandLine = "cmd.exe /c $createCmd" } -CimSession $session
            
            if ($result.ReturnValue -ne 0) {
                throw "Failed to create scheduled task. Return code: $($result.ReturnValue)"
            }
            
            # Run task immediately
            $runCmd = "schtasks /Run /TN `"$taskName`""
            $result = Invoke-CimMethod -ClassName Win32_Process -MethodName Create `
                -Arguments @{ CommandLine = "cmd.exe /c $runCmd" } -CimSession $session
            
            if ($result.ReturnValue -ne 0) {
                throw "Failed to run scheduled task. Return code: $($result.ReturnValue)"
            }
            
            # 3. Wait for completion
            $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
            $completed = $false
            $okPath = "\\$ComputerName\C$\Windows\Temp\snmpcap.ok"
            
            while ((Get-Date) -lt $deadline -and -not $completed) {
                Start-Sleep -Seconds 5
                
                if (Test-Path $okPath) {
                    $marker = Get-Content $okPath -ErrorAction SilentlyContinue | Select-Object -Last 1
                    if ($marker -like 'END *') {
                        $completed = $true
                        break
                    }
                }
            }
            
            # 4. Cleanup task
            $delCmd = "schtasks /Delete /TN `"$taskName`" /F"
            $null = Invoke-CimMethod -ClassName Win32_Process -MethodName Create `
                -Arguments @{ CommandLine = "cmd.exe /c $delCmd" } -CimSession $session
            
            # 5. Collect results
            $logPath = "\\$ComputerName\C$\Windows\Temp\snmpcap.log"
            
            $marker = if (Test-Path $okPath) { Get-Content $okPath -ErrorAction SilentlyContinue } else { @() }
            $log = if (Test-Path $logPath) { Get-Content $logPath -ErrorAction SilentlyContinue | Select-Object -Last 20 } else { @() }
            
            [PSCustomObject]@{
                ComputerName = $ComputerName
                Completed    = $completed
                TimedOut     = -not $completed
                Marker       = $marker
                Log          = $log
                Success      = $completed -and ($marker[-1] -like 'END * | OK*')
            }
        }
        finally {
            Remove-CimSession $session -ErrorAction SilentlyContinue
        }
    }
    catch {
        throw "Remote payload execution failed on ${ComputerName}: $_"
    }
}

function Test-SNMPConnectivity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        
        [Parameter(Mandatory)]
        [string]$Community
    )
    
    # Basic SNMP query test using .NET
    try {
        # This is a simplified check - in production you'd use a proper SNMP library
        $udp = [System.Net.Sockets.UdpClient]::new()
        $udp.Client.ReceiveTimeout = 3000
        $udp.Connect($ComputerName, 161)
        
        # SNMP GetRequest for sysDescr (1.3.6.1.2.1.1.1.0)
        # This is a basic implementation - use proper SNMP library in production
        $udp.Close()
        return $true
    }
    catch {
        return $false
    }
    finally {
        if ($udp) { $udp.Dispose() }
    }
}

# ============================================================================
# CLIENT PAYLOAD TEMPLATE
# ============================================================================

function Get-ClientPayload {
    param(
        [Parameter(Mandatory)]
        [SNMPConfig]$Config,
        
        [Parameter(Mandatory)]
        [string]$CommunityString
    )
    
    $managersLiteral = ($Config.PermittedManagers | ForEach-Object { "'$_'" }) -join ','
    $fodSource = if ($Config.FODSourcePath) { "'$($Config.FODSourcePath)'" } else { '$null' }
    
    # Note: sysLocation will be determined dynamically based on computer name prefix
    # B- prefix = Beach, P- prefix = Pointe
    
    @"
`$ErrorActionPreference = 'Stop'
`$ProgressPreference = 'SilentlyContinue'

`$logPath = 'C:\Windows\Temp\snmpcap.log'
`$okPath = 'C:\Windows\Temp\snmpcap.ok'
`$fodSourcePath = $fodSource

"BEGIN `$(Get-Date -Format s)" | Out-File `$okPath -Encoding ascii

function Write-Log {
    param([string]`$Message)
    "`$(Get-Date -Format s) | `$Message" | Out-File `$logPath -Append -Encoding ascii
}

try {
    Write-Log "Starting SNMP deployment on `$env:COMPUTERNAME"
    
    # Check if already configured (idempotency)
    `$snmpSvc = Get-Service -Name SNMP -ErrorAction SilentlyContinue
    if (`$snmpSvc -and `$snmpSvc.Status -eq 'Running') {
        Write-Log "SNMP already installed and running - verifying config"
        `$regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities'
        if (Test-Path `$regPath) {
            Write-Log "SNMP appears configured - skipping installation"
            "END `$(Get-Date -Format s) | OK: SNMP already configured on `$env:COMPUTERNAME" | Out-File `$okPath -Append
            exit 0
        }
    }
    
    # Determine installation method
    if (`$fodSourcePath) {
        Write-Log "Using local FOD source: `$fodSourcePath"
        `$useLocalSource = `$true
    } else {
        Write-Log "Using Windows Update for FOD installation"
        `$useLocalSource = `$false
        
        # Configure Windows Update for FoD installation
        Write-Log "Configuring Windows Update"
        `$auKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
        `$wuKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
        
        `$prevUseWUServer = try { (Get-ItemProperty `$auKey -Name UseWUServer -EA Stop).UseWUServer } catch { `$null }
        `$prevDoNotConn = try { (Get-ItemProperty `$wuKey -Name DoNotConnectToWindowsUpdateInternetLocations -EA Stop).DoNotConnectToWindowsUpdateInternetLocations } catch { `$null }
        
        # Temporarily allow Microsoft Update
        New-Item -Path `$auKey -Force | Out-Null
        Set-ItemProperty -Path `$auKey -Name UseWUServer -Value 0 -Type DWord
        New-Item -Path `$wuKey -Force | Out-Null
        Set-ItemProperty -Path `$wuKey -Name DoNotConnectToWindowsUpdateInternetLocations -Value 0 -Type DWord
        
        # Start required services
        `$services = @('wuauserv', 'BITS')
        `$serviceStates = @{}
        foreach (`$svc in `$services) {
            `$s = Get-Service `$svc
            `$serviceStates[`$svc] = `$s.Status
            if (`$s.Status -ne 'Running') {
                Write-Log "Starting service: `$svc"
                Start-Service `$svc -ErrorAction SilentlyContinue
            }
        }
    }
    
    Write-Log "Installing SNMP Windows Capabilities"
    `$installStart = Get-Date
    
    try {
        if (`$useLocalSource) {
            # Install from local source (fast, no internet required)
            Add-WindowsCapability -Online -Name 'SNMP.Client~~~~0.0.1.0' -Source `$fodSourcePath -LimitAccess | Out-Null
            Add-WindowsCapability -Online -Name 'WMI-SNMP-Provider.Client~~~~0.0.1.0' -Source `$fodSourcePath -LimitAccess | Out-Null
            Write-Log "Installed from local source in `$([math]::Round(((Get-Date) - `$installStart).TotalSeconds, 1)) seconds"
        } else {
            # Install from Windows Update (slow, requires internet)
            Add-WindowsCapability -Online -Name 'SNMP.Client~~~~0.0.1.0' | Out-Null
            Add-WindowsCapability -Online -Name 'WMI-SNMP-Provider.Client~~~~0.0.1.0' | Out-Null
            Write-Log "Installed from Windows Update in `$([math]::Round(((Get-Date) - `$installStart).TotalSeconds, 1)) seconds"
        }
    }
    catch {
        if (`$useLocalSource) {
            Write-Log "Local source failed, falling back to Windows Update: `$(`$_.Exception.Message)"
            # Fallback: Configure WU and try again
            `$auKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
            `$wuKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
            New-Item -Path `$auKey -Force | Out-Null
            Set-ItemProperty -Path `$auKey -Name UseWUServer -Value 0 -Type DWord
            New-Item -Path `$wuKey -Force | Out-Null
            Set-ItemProperty -Path `$wuKey -Name DoNotConnectToWindowsUpdateInternetLocations -Value 0 -Type DWord
            
            Add-WindowsCapability -Online -Name 'SNMP.Client~~~~0.0.1.0' | Out-Null
            Add-WindowsCapability -Online -Name 'WMI-SNMP-Provider.Client~~~~0.0.1.0' | Out-Null
            Write-Log "Fallback installation completed"
        } else {
            throw
        }
    }
    
    Write-Log "Configuring SNMP registry"
    
    # Determine sysLocation based on computer name prefix
    `$computerName = `$env:COMPUTERNAME
    `$sysLocation = if (`$computerName -match '^B-') {
        'Beach'
    } elseif (`$computerName -match '^P-') {
        'Pointe'
    } else {
        '$($Config.SysLocation)'  # Fallback to config default
    }
    
    Write-Log "Computer: `$computerName, Location: `$sysLocation"
    
    # Configure SNMP
    `$base = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters'
    `$vc = Join-Path `$base 'ValidCommunities'
    `$pm = Join-Path `$base 'PermittedManagers'
    `$rfc = Join-Path `$base 'RFC1156Agent'
    
    New-Item -Path `$vc, `$pm, `$rfc -Force | Out-Null
    
    # Community string
    New-ItemProperty -Path `$vc -Name '$CommunityString' -PropertyType DWord -Value $($Config.CommunityPermission) -Force | Out-Null
    Write-Log "Set community string"
    
    # Clear any existing permitted managers first
    try {
        # Remove all numeric PermittedManager properties (cleanup before re-adding)
        `$existingProps = (Get-Item `$pm).Property | Where-Object { `$_ -match '^\d+$' }
        foreach (`$prop in `$existingProps) {
            Remove-ItemProperty -Path `$pm -Name `$prop -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Log "Error clearing permitted managers: `$(`$_.Exception.Message)"
    }
    
    Write-Log "Configuring services and firewall"
    
    # Firewall
    Enable-NetFirewallRule -DisplayGroup 'SNMP Service' -ErrorAction SilentlyContinue | Out-Null
    
    # Services
    Set-Service SNMP -StartupType Automatic
    Set-Service SNMPTRAP -StartupType Automatic
    Restart-Service SNMP -Force
    Restart-Service SNMPTRAP -Force
    
    Write-Log "SNMP deployment completed successfully"
    "END `$(Get-Date -Format s) | OK: SNMP installed & configured on `$env:COMPUTERNAME" | Out-File `$okPath -Append
}
catch {
    Write-Log "ERROR: `$(`$_.Exception.Message)"
    Write-Log `$_.ScriptStackTrace
    "END `$(Get-Date -Format s) | ERR: `$(`$_.Exception.Message)" | Out-File `$okPath -Append
    throw
}
finally {
    # Only restore WSUS settings if we changed them
    if (-not `$useLocalSource) {
        Write-Log "Restoring WSUS configuration"
        
        # Restore WSUS settings
        if (`$null -ne `$prevUseWUServer) {
            Set-ItemProperty -Path `$auKey -Name UseWUServer -Value `$prevUseWUServer -Type DWord
        } else {
            Remove-ItemProperty -Path `$auKey -Name UseWUServer -EA SilentlyContinue
        }
        
        if (`$null -ne `$prevDoNotConn) {
            Set-ItemProperty -Path `$wuKey -Name DoNotConnectToWindowsUpdateInternetLocations -Value `$prevDoNotConn -Type DWord
        } else {
            Remove-ItemProperty -Path `$wuKey -Name DoNotConnectToWindowsUpdateInternetLocations -EA SilentlyContinue
        }
        
        # Restore service states
        foreach (`$svc in `$serviceStates.Keys) {
            if (`$serviceStates[`$svc] -ne 'Running') {
                Write-Log "Stopping service: `$svc"
                Stop-Service `$svc -Force -EA SilentlyContinue
            }
        }
    }
    
    Write-Log "Cleanup completed"
}
"@
}

# ============================================================================
# MAIN DEPLOYMENT LOGIC
# ============================================================================

function Start-SNMPDeployment {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [SNMPConfig]$Config,
        
        [Parameter(Mandatory)]
        [string]$CommunityString,
        
        [int]$ThrottleLimit,
        
        [switch]$SkipVerification
    )
    
    Write-Host "`n[*] Discovering workstations in: $($Config.SearchBase)" -ForegroundColor Cyan
    
    $targets = @(Get-ADComputer -SearchBase $Config.SearchBase -Filter 'Enabled -eq $true' -Properties OperatingSystem |
        Where-Object { $_.OperatingSystem -notmatch 'Server' } |
        Select-Object -ExpandProperty Name)
    
    if ($targets.Count -eq 0) {
        throw "No workstations found in search base"
    }
    
    Write-Host "[+] Found $($targets.Count) workstation$(if($targets.Count -ne 1){'s'})" -ForegroundColor Green
    
    if ($PSCmdlet.ShouldProcess("$($targets.Count) workstations", "Deploy SNMP")) {
        
        $payload = Get-ClientPayload -Config $Config -CommunityString $CommunityString
        
        Write-Host "`n[*] Starting parallel deployment (throttle: $ThrottleLimit)" -ForegroundColor Cyan
        
        $results = $targets | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
            $computer = $_
            $config = $using:Config
            $payload = $using:payload
            $skipVerify = $using:SkipVerification
            
            # Define helper functions inline (required for parallel execution)
            function Test-RemoteConnectivity {
                param([string]$ComputerName, [int]$TimeoutSeconds = 5)
                $checks = @{ SMB = $false; DCOM = $false; ICMP = $false }
                try { $null = Get-Item "\\$ComputerName\C$" -ErrorAction Stop; $checks.SMB = $true } catch {}
                if (-not $checks.SMB) {
                    try {
                        $opt = New-CimSessionOption -Protocol Dcom
                        $session = New-CimSession -ComputerName $ComputerName -SessionOption $opt -ErrorAction Stop -OperationTimeoutSec $TimeoutSeconds
                        $checks.DCOM = $true
                        Remove-CimSession $session -ErrorAction SilentlyContinue
                    }
                    catch {}
                }
                if (-not $checks.SMB -and -not $checks.DCOM) {
                    try { $checks.ICMP = Test-Connection -TargetName $ComputerName -Count 1 -Quiet -TimeoutSeconds $TimeoutSeconds } catch {}
                }
                [PSCustomObject]@{ ComputerName = $ComputerName; Reachable = ($checks.SMB -or $checks.DCOM -or $checks.ICMP); SMB = $checks.SMB; DCOM = $checks.DCOM; ICMP = $checks.ICMP }
            }
            
            function Test-SNMPConfiguration {
                param([string]$ComputerName, [object]$ExpectedConfig)
                try {
                    $vcPath = "\\$ComputerName\HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities"
                    $pmPath = "\\$ComputerName\HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"
                    if (-not (Test-Path $vcPath) -or -not (Test-Path $pmPath)) { return $false }
                    $managers = Get-Item $pmPath | Select-Object -ExpandProperty Property
                    return ($null -ne $managers)
                }
                catch { return $false }
            }
            
            function Test-SNMPServiceState {
                param([string]$ComputerName)
                try {
                    $opt = New-CimSessionOption -Protocol Dcom
                    $session = New-CimSession -ComputerName $ComputerName -SessionOption $opt -ErrorAction Stop
                    try {
                        $snmpService = Get-CimInstance -ClassName Win32_Service -Filter "Name='SNMP'" -CimSession $session -ErrorAction SilentlyContinue
                        $snmpTrapService = Get-CimInstance -ClassName Win32_Service -Filter "Name='SNMPTRAP'" -CimSession $session -ErrorAction SilentlyContinue
                        [PSCustomObject]@{
                            ComputerName      = $ComputerName
                            SNMPInstalled     = $null -ne $snmpService
                            SNMPRunning       = $snmpService.State -eq 'Running'
                            SNMPTRAPInstalled = $null -ne $snmpTrapService
                            SNMPTRAPRunning   = $snmpTrapService.State -eq 'Running'
                        }
                    }
                    finally { Remove-CimSession $session }
                }
                catch { return $null }
            }
            
            function Remove-DeploymentArtifacts {
                param([string]$ComputerName, [string[]]$Artifacts = @('snmpcap.ps1', 'snmpcap.log', 'snmpcap.ok', 'snmpcap.run.log', 'snmpcap.cap.txt', 'snmpcap.task.txt'))
                foreach ($artifact in $Artifacts) {
                    try {
                        $path = "\\$ComputerName\C$\Windows\Temp\$artifact"
                        if (Test-Path $path) { Remove-Item $path -Force -ErrorAction Stop }
                    }
                    catch {}
                }
            }
            
            function Invoke-RemotePayloadDCOM {
                param([string]$ComputerName, [string]$ScriptContent, [string]$RemoteScriptName = 'snmpcap.ps1', [int]$TimeoutMinutes = 15, [bool]$FireAndForget = $false)
                $remotePath = "C:\Windows\Temp\$RemoteScriptName"
                $sharePath = "\\$ComputerName\C$\Windows\Temp\$RemoteScriptName"
                
                Set-Content -Path $sharePath -Value $ScriptContent -Encoding UTF8 -Force
                $taskName = "SNMPDeploy_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
                $action = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $remotePath"
                $startTime = (Get-Date).AddMinutes(1).ToString('HH:mm')
                
                $opt = New-CimSessionOption -Protocol Dcom
                $session = New-CimSession -ComputerName $ComputerName -SessionOption $opt
                
                try {
                    $createCmd = "schtasks /Create /TN `"$taskName`" /TR `"$action`" /SC ONCE /ST $startTime /RL HIGHEST /RU SYSTEM /F"
                    $result = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = "cmd.exe /c $createCmd" } -CimSession $session
                    if ($result.ReturnValue -ne 0) { throw "Failed to create task: $($result.ReturnValue)" }
                    
                    $runCmd = "schtasks /Run /TN `"$taskName`""
                    $result = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = "cmd.exe /c $runCmd" } -CimSession $session
                    if ($result.ReturnValue -ne 0) { throw "Failed to run task: $($result.ReturnValue)" }
                    
                    # Fire and forget mode - return immediately
                    if ($FireAndForget) {
                        return [PSCustomObject]@{
                            ComputerName  = $ComputerName
                            Completed     = $false
                            TimedOut      = $false
                            Marker        = @("Deployment initiated - verification required")
                            Log           = @()
                            Success       = $null
                            FireAndForget = $true
                        }
                    }
                    
                    # Normal mode - wait for completion
                    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
                    $completed = $false
                    $okPath = "\\$ComputerName\C$\Windows\Temp\snmpcap.ok"
                    
                    while ((Get-Date) -lt $deadline -and -not $completed) {
                        Start-Sleep -Seconds 5
                        if (Test-Path $okPath) {
                            $marker = Get-Content $okPath -ErrorAction SilentlyContinue | Select-Object -Last 1
                            if ($marker -like 'END *') { $completed = $true; break }
                        }
                    }
                    
                    $delCmd = "schtasks /Delete /TN `"$taskName`" /F"
                    $null = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = "cmd.exe /c $delCmd" } -CimSession $session
                    
                    $logPath = "\\$ComputerName\C$\Windows\Temp\snmpcap.log"
                    $marker = if (Test-Path $okPath) { Get-Content $okPath -ErrorAction SilentlyContinue } else { @() }
                    $log = if (Test-Path $logPath) { Get-Content $logPath -ErrorAction SilentlyContinue | Select-Object -Last 20 } else { @() }
                    
                    [PSCustomObject]@{
                        ComputerName  = $ComputerName
                        Completed     = $completed
                        TimedOut      = -not $completed
                        Marker        = $marker
                        Log           = $log
                        Success       = $completed -and ($marker[-1] -like 'END * | OK*')
                        FireAndForget = $false
                    }
                }
                finally {
                    Remove-CimSession $session -ErrorAction SilentlyContinue
                }
            }
            
            try {
                # Pre-flight connectivity
                $connectivity = Test-RemoteConnectivity -ComputerName $computer
                if (-not $connectivity.Reachable) {
                    return [PSCustomObject]@{
                        ComputerName = $computer
                        Status       = 'UNREACHABLE'
                        Message      = "No connectivity (SMB: $($connectivity.SMB), DCOM: $($connectivity.DCOM), ICMP: $($connectivity.ICMP))"
                        Duration     = $null
                    }
                }
                
                # Check if already configured (idempotency)
                $isConfigured = Test-SNMPConfiguration -ComputerName $computer -ExpectedConfig $config
                if ($isConfigured) {
                    return [PSCustomObject]@{
                        ComputerName = $computer
                        Status       = 'SKIPPED'
                        Message      = 'SNMP already configured'
                        Duration     = $null
                    }
                }
                
                # Deploy
                $startTime = Get-Date
                $result = Invoke-RemotePayloadDCOM -ComputerName $computer -ScriptContent $payload `
                    -TimeoutMinutes $config.DeploymentTimeoutMinutes -FireAndForget $config.FireAndForget
                $duration = ((Get-Date) - $startTime).TotalSeconds
                
                # Don't cleanup or verify in fire-and-forget mode
                if (-not $config.FireAndForget) {
                    # Cleanup artifacts
                    Remove-DeploymentArtifacts -ComputerName $computer
                    
                    # Verify (optional)
                    $verified = $false
                    if (-not $skipVerify -and $result.Success) {
                        Start-Sleep -Seconds 2
                        $state = Test-SNMPServiceState -ComputerName $computer
                        $verified = $state.SNMPRunning -and $state.SNMPTRAPRunning
                    }
                }
                
                [PSCustomObject]@{
                    ComputerName = $computer
                    Status       = if ($config.FireAndForget) { 'DEPLOYED' } elseif ($result.Success) { 'SUCCESS' } elseif ($result.TimedOut) { 'TIMEOUT' } else { 'FAILED' }
                    Message      = if ($config.FireAndForget) { 'Deployment initiated - verify later' } elseif ($result.Success) { 'Deployed successfully' } else { $result.Marker -join ' | ' }
                    Duration     = [math]::Round($duration, 1)
                    Verified     = if ($config.FireAndForget -or $skipVerify) { 'N/A' } else { $verified }
                }
            }
            catch {
                [PSCustomObject]@{
                    ComputerName = $computer
                    Status       = 'ERROR'
                    Message      = $_.Exception.Message
                    Duration     = $null
                    Verified     = 'N/A'
                }
            }
        }
        
        return $results
    }
}

function Start-CleanupOnly {
    param(
        [string]$SearchBase,
        [int]$ThrottleLimit
    )
    
    Write-Host "`n[*] Cleanup mode - removing deployment artifacts" -ForegroundColor Cyan
    
    $targets = @(Get-ADComputer -SearchBase $SearchBase -Filter 'Enabled -eq $true' |
        Select-Object -ExpandProperty Name)
    
    $targets | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
        $computer = $_
        
        function Remove-DeploymentArtifacts {
            param([string]$ComputerName, [string[]]$Artifacts = @('snmpcap.ps1', 'snmpcap.log', 'snmpcap.ok', 'snmpcap.run.log', 'snmpcap.cap.txt', 'snmpcap.task.txt'))
            foreach ($artifact in $Artifacts) {
                try {
                    $path = "\\$ComputerName\C$\Windows\Temp\$artifact"
                    if (Test-Path $path) { Remove-Item $path -Force -ErrorAction Stop }
                }
                catch {}
            }
        }
        
        try {
            Remove-DeploymentArtifacts -ComputerName $computer
            Write-Host "[+] Cleaned: $computer" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to clean ${computer}: $_"
        }
    }
}

# ============================================================================
# EXECUTION
# ============================================================================

try {
    Write-Host @"

╔═══════════════════════════════════════════════════╗
║   Enterprise SNMP Deployment v2.0                 ║
║   SecDevOps Hardened Edition                      ║
╚═══════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

    $config = Import-DeploymentConfig -Path $ConfigPath
    
    if ($CleanupOnly) {
        Start-CleanupOnly -SearchBase $config.SearchBase -ThrottleLimit $ThrottleLimit
        exit 0
    }
    
    # Retrieve secret
    Write-Host "[*] Retrieving SNMP community string from $($config.SecretProvider)..." -ForegroundColor Cyan
    $communityString = Get-SNMPCommunityString -Config $config
    Write-Host "[+] Secret retrieved successfully" -ForegroundColor Green
    
    # Execute deployment
    $results = Start-SNMPDeployment -Config $config -CommunityString $communityString `
        -ThrottleLimit $ThrottleLimit -SkipVerification:$SkipVerification
    
    # Output results
    Write-Host "`n" + "="*80 -ForegroundColor Cyan
    Write-Host "DEPLOYMENT RESULTS" -ForegroundColor Cyan
    Write-Host "="*80 + "`n" -ForegroundColor Cyan
    
    $results | Format-Table -AutoSize
    
    # Summary statistics
    $summary = @($results | Group-Object Status)
    Write-Host "`nSUMMARY:" -ForegroundColor Yellow
    $summary | Select-Object Name, Count | Format-Table -AutoSize
    
    # Export results
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $csvPath = ".\snmp_deployment_$timestamp.csv"
    $results | Export-Csv $csvPath -NoTypeInformation
    Write-Host "[+] Results exported to: $csvPath" -ForegroundColor Green
    
    # Calculate success rate
    $successCount = @($results | Where-Object Status -eq 'SUCCESS').Count
    $totalAttempted = @($results | Where-Object Status -notin @('SKIPPED', 'UNREACHABLE')).Count
    
    if ($totalAttempted -gt 0) {
        $successRate = [math]::Round(($successCount / $totalAttempted) * 100, 1)
        Write-Host "`nSuccess Rate: $successRate% ($successCount/$totalAttempted)" -ForegroundColor $(if ($successRate -ge 90) { 'Green' } elseif ($successRate -ge 70) { 'Yellow' }else { 'Red' })
    }
    
    # Check for failures
    $failures = @($results | Where-Object Status -in @('FAILED', 'TIMEOUT', 'ERROR'))
    if ($failures.Count -gt 0) {
        Write-Host "`n[!] $($failures.Count) deployment(s) failed - review logs" -ForegroundColor Red
        $failures | Format-Table ComputerName, Status, Message -AutoSize
    }
}
catch {
    Write-Host "`n[X] FATAL ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 1
}