#requires -Version 7.0
#requires -Modules ActiveDirectory
<#
  SNMP + WMI-SNMP rollout via DCOM/SMB (no WinRM) - V3
  - Uses config file for settings
  - Downloads FoD from Microsoft online (no local source)
  - Configures SNMP for LibreNMS communication
  - Targets discovered by short "Name"
  - Pushes payload to C:\Windows\Temp\snmpcap.ps1
  - Runs as SYSTEM via Scheduled Task
  - Temporarily forces Microsoft Update (bypass WSUS) to install FoD
  - Configures SNMP registry, services, firewall
  - Per-host reachability checks inside the parallel block
  - Idempotent: safe to re-run on configured machines
  - Verifies FoD installation actually worked
  - Configures both SNMP-WMI bridge and direct WMI access
#>

param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ })]
    [string]$ConfigPath
)

Import-Module ActiveDirectory

# ====================== CONFIG LOADING ======================
function Get-SNMPCommunityString {
    param(
        [string]$SecretPath,
        [string]$SecretProvider = 'File'
    )
    
    if ($SecretProvider -eq 'File') {
        if (-not $SecretPath -or -not (Test-Path $SecretPath)) {
            throw "SecretPath required for File provider: $SecretPath"
        }
        $encrypted = (Get-Content $SecretPath -Raw).Trim()
        $secure = ConvertTo-SecureString $encrypted
        return [System.Net.NetworkCredential]::new('', $secure).Password
    }
    else {
        throw "Unsupported SecretProvider: $SecretProvider"
    }
}

if (-not (Test-Path $ConfigPath)) {
    throw "Config file not found: $ConfigPath"
}

$config = Get-Content $ConfigPath -Raw | ConvertFrom-Json

# Validate required config fields
if (-not $config.SearchBase) { throw "SearchBase is required in config" }
if (-not $config.PermittedManagers) { throw "PermittedManagers is required in config" }
if (-not $config.SecretPath) { throw "SecretPath is required in config" }

# Load community string from secret
$SnmpCommunity = Get-SNMPCommunityString -SecretPath $config.SecretPath -SecretProvider $config.SecretProvider
$CommunityPerm = if ($config.CommunityPermission) { $config.CommunityPermission } else { 4 }
$PermittedManagers = $config.PermittedManagers
$SysContact = if ($config.SysContact) { $config.SysContact } else { 'IT Department' }
$SysLocation = if ($config.SysLocation) { $config.SysLocation } else { 'Unknown' }
$SearchBase = $config.SearchBase
$ThrottleLimit = if ($config.ThrottleLimit) { $config.ThrottleLimit } else { 20 }
$DeploymentTimeoutMinutes = if ($config.DeploymentTimeoutMinutes) { $config.DeploymentTimeoutMinutes } else { 15 }

# ================== CLIENT PAYLOAD ==================
$clientTemplate = @'
$ErrorActionPreference = 'Stop'
"BEGIN $(Get-Date -Format s)" | Out-File 'C:\Windows\Temp\snmpcap.ok' -Encoding ascii -Append
Start-Transcript -Path 'C:\Windows\Temp\snmpcap.log' -Append

try {
  # ===== IDEMPOTENCY CHECK =====
  # Verify ALL registry keys match expected configuration before skipping
  $base = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters'
  $vc   = Join-Path $base 'ValidCommunities'
  $pm   = Join-Path $base 'PermittedManagers'
  $rfc  = Join-Path $base 'RFC1156Agent'
  
  $allConfigured = $true
  $missingItems = @()
  
  # Check SNMP service is running
  $snmpSvc = Get-Service -Name SNMP -ErrorAction SilentlyContinue
  if (-not $snmpSvc -or $snmpSvc.Status -ne 'Running') {
    $allConfigured = $false
    $missingItems += "SNMP service not running"
  }
  
  # Check ValidCommunities - community string
  if (-not (Test-Path $vc)) {
    $allConfigured = $false
    $missingItems += "ValidCommunities registry key missing"
  } else {
    $existingComm = (Get-ItemProperty $vc -Name '__COMMUNITY__' -ErrorAction SilentlyContinue).'__COMMUNITY__'
    if ($existingComm -ne __COMM_PERM__) {
      $allConfigured = $false
      $missingItems += "Community string mismatch or missing"
    }
  }
  
  # Check PermittedManagers - all managers must exist
  if (-not (Test-Path $pm)) {
    $allConfigured = $false
    $missingItems += "PermittedManagers registry key missing"
  } else {
    $expectedManagers = @(__MANAGERS__) | ForEach-Object { $_.ToString().Trim() } | Sort-Object
    $existingManagers = (Get-Item $pm).Property | Where-Object { $_ -match '^\d+$' } | 
      ForEach-Object { (Get-ItemProperty $pm -Name $_).$_.ToString().Trim() } | Sort-Object
    
    if ($expectedManagers.Count -ne $existingManagers.Count) {
      $allConfigured = $false
      $missingItems += "PermittedManagers count mismatch (expected $($expectedManagers.Count), found $($existingManagers.Count))"
    } else {
      for ($i = 0; $i -lt $expectedManagers.Count; $i++) {
        if ($expectedManagers[$i] -ne $existingManagers[$i]) {
          $allConfigured = $false
          $missingItems += "PermittedManagers mismatch: expected '$($expectedManagers[$i])', found '$($existingManagers[$i])'"
          break
        }
      }
    }
  }
  
  # Check RFC1156Agent - sysContact, sysLocation, and sysServices
  if (-not (Test-Path $rfc)) {
    $allConfigured = $false
    $missingItems += "RFC1156Agent registry key missing"
  } else {
    $existingContact = (Get-ItemProperty $rfc -Name 'sysContact' -ErrorAction SilentlyContinue).sysContact
    $existingLocation = (Get-ItemProperty $rfc -Name 'sysLocation' -ErrorAction SilentlyContinue).sysLocation
    $existingServices = (Get-ItemProperty $rfc -Name 'sysServices' -ErrorAction SilentlyContinue).sysServices
    
    if ($existingContact -ne '__CONTACT__') {
      $allConfigured = $false
      $missingItems += "sysContact mismatch or missing"
    }
    if ($existingLocation -ne '__LOCATION__') {
      $allConfigured = $false
      $missingItems += "sysLocation mismatch or missing"
    }
    if ($existingServices -ne 0x41) {
      $allConfigured = $false
      $missingItems += "sysServices mismatch or missing (expected 0x41)"
    }
  }
  
  if ($allConfigured) {
    Write-Host "SNMP already configured correctly - all registry keys verified - skipping"
    "END $(Get-Date -Format s) | SKIP: Already configured" | Out-File 'C:\Windows\Temp\snmpcap.ok' -Encoding ascii -Append
    Stop-Transcript | Out-Null
    exit 0
  } else {
    Write-Host "SNMP configuration incomplete or incorrect. Missing/mismatched items:"
    $missingItems | ForEach-Object { Write-Host "  - $_" }
    Write-Host "Proceeding with configuration..."
  }

  # ===== DISK SPACE CHECK (optional, fail-friendly) =====
  $cDrive = Get-PSDrive -Name C
  $freeMB = [math]::Round($cDrive.Free / 1MB, 0)
  if ($freeMB -lt 100) {
    Write-Warning "Low disk space: ${freeMB}MB free on C:\"
    "END $(Get-Date -Format s) | WARN: Low disk space ${freeMB}MB - continuing anyway" | Out-File 'C:\Windows\Temp\snmpcap.ok' -Encoding ascii -Append
  }

  # ===== FORCE Microsoft Update for FoD (skip WSUS) =====
  $auKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
  $wuKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'

  $prevUseWUServer = (Get-ItemProperty -Path $auKey -Name UseWUServer -ErrorAction SilentlyContinue).UseWUServer
  $prevDoNotConn   = (Get-ItemProperty -Path $wuKey -Name DoNotConnectToWindowsUpdateInternetLocations -ErrorAction SilentlyContinue).DoNotConnectToWindowsUpdateInternetLocations

  New-Item -Path $auKey -Force | Out-Null
  Set-ItemProperty -Path $auKey -Name UseWUServer -Value 0 -Type DWord
  New-Item -Path $wuKey -Force | Out-Null
  Set-ItemProperty -Path $wuKey -Name DoNotConnectToWindowsUpdateInternetLocations -Value 0 -Type DWord

  # ensure update services are RUNNING (no restart)
  $wuSvc   = Get-Service -Name wuauserv  -ErrorAction Stop
  $bitsSvc = Get-Service -Name BITS      -ErrorAction Stop
  $wuWasRunning   = $wuSvc.Status  -eq 'Running'
  $bitsWasRunning = $bitsSvc.Status -eq 'Running'
  if (-not $wuWasRunning)   { try { Start-Service wuauserv } catch { & sc.exe start wuauserv | Out-Null } }
  if (-not $bitsWasRunning) { try { Start-Service BITS     } catch { & sc.exe start BITS     | Out-Null } }

  # ===== Install Windows Capabilities from Microsoft Online =====
  Write-Host "Installing SNMP Client from Microsoft..."
  Add-WindowsCapability -Online -Name 'SNMP.Client~~~~0.0.1.0' -ErrorAction Stop | Out-Null
  
  Write-Host "Installing WMI-SNMP Provider from Microsoft..."
  Add-WindowsCapability -Online -Name 'WMI-SNMP-Provider.Client~~~~0.0.1.0' -ErrorAction Stop | Out-Null

  Get-WindowsCapability -Online -Name '*SNMP*' |
    Select-Object Name, State |
    Out-File 'C:\Windows\Temp\snmpcap.cap.txt' -Encoding ascii

  # ===== VERIFY FoD ACTUALLY INSTALLED =====
  $snmpSvc = Get-Service -Name SNMP -ErrorAction SilentlyContinue
  if (-not $snmpSvc) {
    throw "SNMP service not present after FoD install - capability installation failed"
  }
  Write-Host "Verified: SNMP service exists"

  # ===== Configure SNMP registry =====
  Write-Host "Configuring SNMP registry..."
  $base = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters'
  $vc   = Join-Path $base 'ValidCommunities'
  $pm   = Join-Path $base 'PermittedManagers'
  $rfc  = Join-Path $base 'RFC1156Agent'
  
  # Create registry keys with explicit error handling
  try {
    if (-not (Test-Path $vc)) { New-Item -Path $vc -Force | Out-Null }
    if (-not (Test-Path $pm)) { New-Item -Path $pm -Force | Out-Null }
    if (-not (Test-Path $rfc)) { New-Item -Path $rfc -Force | Out-Null }
    Write-Host "Registry keys created/verified"
  }
  catch {
    Write-Host "ERROR creating registry keys: $_"
    throw
  }

  # Community string
  try {
    New-ItemProperty -Path $vc -Name '__COMMUNITY__' -PropertyType DWord -Value __COMM_PERM__ -Force | Out-Null
    Write-Host "Community string configured"
  }
  catch {
    Write-Host "ERROR setting community string: $_"
    throw
  }

  # Permitted managers
  try {
    (Get-Item $pm).Property | Where-Object { $_ -match '^\d+$' } |
      ForEach-Object { Remove-ItemProperty -Path $pm -Name $_ -ErrorAction SilentlyContinue }
    
    $i = 1
    foreach ($m in @(__MANAGERS__)) {
      New-ItemProperty -Path $pm -Name "$i" -Value $m -PropertyType String -Force | Out-Null
      Write-Host "Added permitted manager: $m"
      $i++
    }
  }
  catch {
    Write-Host "ERROR configuring permitted managers: $_"
    throw
  }

  # RFC1156 Agent (sysContact, sysLocation, sysServices)
  try {
    New-ItemProperty -Path $rfc -Name 'sysContact'  -Value '__CONTACT__'  -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $rfc -Name 'sysLocation' -Value '__LOCATION__' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $rfc -Name 'sysServices' -Value 0x41 -PropertyType DWord -Force | Out-Null
    Write-Host "RFC1156 agent configured (sysServices=0x41)"
  }
  catch {
    Write-Host "ERROR configuring RFC1156 agent: $_"
    throw
  }

  # ===== Firewall Configuration =====
  # 1. SNMP inbound from LibreNMS (UDP 161)
  $ruleName = 'SNMP LibreNMS Inbound'
  $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
  if ($existingRule) {
    Remove-NetFirewallRule -DisplayName $ruleName
  }
  New-NetFirewallRule -DisplayName $ruleName `
    -Direction Inbound -Protocol UDP -LocalPort 161 `
    -RemoteAddress __MANAGERS__ -Action Allow `
    -Profile Domain,Private -Enabled True | Out-Null
  Write-Host "Created specific SNMP firewall rule for LibreNMS"

  # 2. WMI inbound from LibreNMS (in case direct WMI polling is used)
  # This enables DCOM/RPC for remote WMI queries
  Enable-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)" -ErrorAction SilentlyContinue | Out-Null
  Write-Host "Enabled WMI firewall rules (for direct WMI access if needed)"

  # ===== Services =====
  Set-Service SNMP -StartupType Automatic
  Set-Service SNMPTRAP -StartupType Automatic
  Restart-Service SNMP -Force
  Restart-Service SNMPTRAP -Force

  Write-Host "SNMP services configured and running"

  "END $(Get-Date -Format s) | OK: SNMP installed & configured on $($env:COMPUTERNAME)" |
    Out-File 'C:\Windows\Temp\snmpcap.ok' -Encoding ascii -Append
}
catch {
  "END $(Get-Date -Format s) | ERR: $($_.Exception.Message)" |
    Out-File 'C:\Windows\Temp\snmpcap.ok' -Encoding ascii -Append
  throw
}
finally {
  # ===== RESTORE WSUS SETTINGS =====
  if (-not (Test-Path $auKey)) { New-Item -Path $auKey -Force | Out-Null }
  if (-not (Test-Path $wuKey)) { New-Item -Path $wuKey -Force | Out-Null }

  if ($null -ne $prevUseWUServer) { Set-ItemProperty -Path $auKey -Name UseWUServer -Value $prevUseWUServer -Type DWord }
  else { Remove-ItemProperty -Path $auKey -Name UseWUServer -ErrorAction SilentlyContinue }

  if ($null -ne $prevDoNotConn) { Set-ItemProperty -Path $wuKey -Name DoNotConnectToWindowsUpdateInternetLocations -Value $prevDoNotConn -Type DWord }
  else { Remove-ItemProperty -Path $wuKey -Name DoNotConnectToWindowsUpdateInternetLocations -ErrorAction SilentlyContinue }

  if (-not $wuWasRunning)   { try { Stop-Service wuauserv } catch { & sc.exe stop wuauserv | Out-Null } }
  if (-not $bitsWasRunning) { try { Stop-Service BITS     } catch { & sc.exe stop BITS     | Out-Null } }

  Stop-Transcript | Out-Null
}
'@

# Replace tokens
$ManagersLiteral = ($PermittedManagers | ForEach-Object { "'$_'" }) -join ','
$ManagersArrayForFirewall = $PermittedManagers -join ','
$clientScript = $clientTemplate.
  Replace('__COMMUNITY__', $SnmpCommunity).
  Replace('__COMM_PERM__', [string]$CommunityPerm).
  Replace('__MANAGERS__', $ManagersLiteral).
  Replace('__CONTACT__', $SysContact).
  Replace('__LOCATION__', $SysLocation)

# Also need to replace the firewall rule's RemoteAddress parameter with the actual IPs
$clientScript = $clientScript -replace '(?<=RemoteAddress )__MANAGERS__', $ManagersArrayForFirewall

# ================= TARGET DISCOVERY =================
Write-Host "`n[*] Discovering workstations in: $SearchBase" -ForegroundColor Cyan
$targets = Get-ADComputer -SearchBase $SearchBase -Filter 'Enabled -eq $true' -Properties OperatingSystem |
           Where-Object { $_.OperatingSystem -notmatch 'Server' } |
           Select-Object -ExpandProperty Name

if (-not $targets) {
  Write-Warning "No workstations found under $SearchBase"
  exit 1
}
Write-Host "[+] Found $($targets.Count) workstation$(if($targets.Count -ne 1){'s'})" -ForegroundColor Green

# =================== PARALLEL ROLLOUT ===================
Write-Host "`n[*] Starting parallel deployment (throttle: $ThrottleLimit, timeout: ${DeploymentTimeoutMinutes}m)" -ForegroundColor Cyan
$results = $targets | ForEach-Object -Parallel {
  $ComputerName = $_

  function Start-RemoteScriptDCOM {
    param(
      [Parameter(Mandatory)][string]$ComputerName,
      [Parameter(Mandatory)][string]$ScriptText,
      [string]$RemoteName = 'snmpcap.ps1',
      [int]$TimeoutMinutes = 15
    )

    # 1) Drop payload via SMB admin share
    $sharePath = "\\$ComputerName\C$\Windows\Temp\$RemoteName"
    Set-Content -Path $sharePath -Value $ScriptText -Encoding UTF8 -Force

    # 2) Schedule as SYSTEM with better timing
    $taskName   = "SNMPCap_$([Guid]::NewGuid().ToString('N'))"
    $remotePwsh = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    $action     = "$remotePwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File C:\Windows\Temp\$RemoteName"
    $startTime  = (Get-Date).AddSeconds(30).ToString('HH:mm')

    $createCmd = "schtasks /Create /TN `"$taskName`" /TR `"$action`" /SC ONCE /ST $startTime /RL HIGHEST /RU SYSTEM /F"
    $runCmd    = "schtasks /Run /TN `"$taskName`""
    $queryCmd  = "schtasks /Query /TN `"$taskName`" /FO LIST"
    $delCmd    = "schtasks /Delete /TN `"$taskName`" /F"

    $opt = New-CimSessionOption -Protocol Dcom
    $s   = New-CimSession -ComputerName $ComputerName -SessionOption $opt
    try {
      foreach ($cmd in @($createCmd, $runCmd)) {
        $res = Invoke-CimMethod -ClassName Win32_Process -Namespace root\cimv2 -CimSession $s `
          -MethodName Create -Arguments @{ CommandLine = "cmd.exe /c $cmd" }
        if ($res.ReturnValue -ne 0) { throw "Process create failed (cmd='$cmd') RC=$($res.ReturnValue)" }
      }

      $okPath  = "\\$ComputerName\C$\Windows\Temp\snmpcap.ok"
      $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
      do {
        Start-Sleep 3
        if (Test-Path $okPath) {
          $marker = Get-Content $okPath -EA SilentlyContinue | Select-Object -Last 2
          if ($marker -and ($marker[-1] -like 'END *')) { break }
        }
        [void](Invoke-CimMethod -ClassName Win32_Process -Namespace root\cimv2 -CimSession $s `
          -MethodName Create -Arguments @{ CommandLine = "cmd.exe /c $queryCmd > C:\Windows\Temp\snmpcap.task.txt 2>&1" })
      } while ((Get-Date) -lt $deadline)

      [void](Invoke-CimMethod -ClassName Win32_Process -Namespace root\cimv2 -CimSession $s `
        -MethodName Create -Arguments @{ CommandLine = "cmd.exe /c $delCmd" })
    }
    finally {
      Remove-CimSession $s
    }

    $okPath  = "\\$ComputerName\C$\Windows\Temp\snmpcap.ok"
    $logPath = "\\$ComputerName\C$\Windows\Temp\snmpcap.log"
    $runPath = "\\$ComputerName\C$\Windows\Temp\snmpcap.run.log"

    $marker = if (Test-Path $okPath)  { Get-Content $okPath  -EA SilentlyContinue | Select-Object -Last 2 } else { $null }
    $runTail= if (Test-Path $runPath) { Get-Content $runPath -EA SilentlyContinue | Select-Object -Last 15 } else { $null }
    $logTail= if (Test-Path $logPath) { Get-Content $logPath -EA SilentlyContinue | Select-Object -Last 15 } else { $null }

    [pscustomobject]@{
      Computer = $ComputerName
      Marker   = $marker
      RunTail  = $runTail
      LogTail  = $logTail
    }
  }

  try {
    # --------- Reachability checks (inside parallel block) ---------
    $reachable = $false

    # SMB admin share
    try {
      Get-Item "\\$ComputerName\C$\Windows\Temp" -ErrorAction Stop | Out-Null
      $reachable = $true
    } catch {}

    # DCOM/CIM
    if (-not $reachable) {
      try {
        $opt = New-CimSessionOption -Protocol Dcom
        $tmp = New-CimSession -ComputerName $ComputerName -SessionOption $opt -ErrorAction Stop
        Remove-CimSession $tmp
        $reachable = $true
      } catch {}
    }

    # IPv4 ICMP (optional)
    if (-not $reachable) {
      try {
        $reachable = Test-Connection -TargetName $ComputerName -IPv4 -Count 1 -Quiet
      } catch { $reachable = $false }
    }

    if (-not $reachable) {
      return [pscustomobject]@{
        Computer = $ComputerName
        Status   = 'SKIP'
        Message  = 'SMB/DCOM/IPv4 ping unreachable'
      }
    }
    # -------------------- End reachability --------------------

    # Run the payload
    $res = Start-RemoteScriptDCOM -ComputerName $ComputerName -ScriptText $using:clientScript -TimeoutMinutes $using:DeploymentTimeoutMinutes
    $ok  = ($res.Marker -is [array]) -and ($res.Marker[-1] -like 'END * | OK*')
    $skip = ($res.Marker -is [array]) -and ($res.Marker[-1] -like 'END * | SKIP*')

    [pscustomobject]@{
      Computer = $ComputerName
      Status   = if ($ok) { 'OK' } elseif ($skip) { 'SKIP' } else { 'CHECK' }
      Message  = ($res.Marker -join ' | ')
      RunTail  = ($res.RunTail -join ' | ')
      LogTail  = ($res.LogTail -join ' | ')
    }
  }
  catch {
    [pscustomobject]@{ Computer = $ComputerName; Status = 'ERR'; Message = $_.Exception.Message }
  }
} -ThrottleLimit $ThrottleLimit

# ===================== OUTPUT =======================
Write-Host "`n" + "="*80 -ForegroundColor Cyan
Write-Host "DEPLOYMENT RESULTS" -ForegroundColor Cyan
Write-Host "="*80 + "`n" -ForegroundColor Cyan

$results | Format-Table -AutoSize

# Summary statistics
$summary = @($results | Group-Object Status)
Write-Host "`nSUMMARY:" -ForegroundColor Yellow
$summary | Select-Object Name, Count | Format-Table -AutoSize

$stamp = Get-Date -Format yyyyMMdd_HHmmss
$csvPath = ".\snmp_deployment_$stamp.csv"
$results | Export-Csv $csvPath -NoTypeInformation
Write-Host "`n[+] Results exported to: $csvPath" -ForegroundColor Green

# Calculate success rate (exclude SKIPs from success rate calculation)
$successCount = @($results | Where-Object Status -eq 'OK').Count
$skippedCount = @($results | Where-Object { $_.Status -eq 'SKIP' -and $_.Message -notlike '*Already configured*' }).Count
$alreadyConfigured = @($results | Where-Object { $_.Status -eq 'SKIP' -and $_.Message -like '*Already configured*' }).Count
$totalAttempted = @($results | Where-Object Status -notin @('SKIP')).Count + $alreadyConfigured

if ($totalAttempted -gt 0) {
    $successRate = [math]::Round((($successCount + $alreadyConfigured) / $totalAttempted) * 100, 1)
    Write-Host "`nSuccess Rate: $successRate% ($successCount newly configured + $alreadyConfigured already OK / $totalAttempted attempted)" -ForegroundColor $(if ($successRate -ge 90) { 'Green' } elseif ($successRate -ge 70) { 'Yellow' } else { 'Red' })
}

if ($skippedCount -gt 0) {
    Write-Host "[i] $skippedCount machine(s) skipped due to unreachability" -ForegroundColor Cyan
}

# Check for failures
$failures = @($results | Where-Object Status -in @('CHECK', 'ERR'))
if ($failures.Count -gt 0) {
    Write-Host "`n[!] $($failures.Count) deployment(s) need attention - review logs" -ForegroundColor Yellow
    $failures | Format-Table Computer, Status, Message -AutoSize
}

Write-Host "`n[*] Next steps:" -ForegroundColor Cyan
Write-Host "  1. Test SNMP from LibreNMS: snmpwalk -v2c -c <community> <hostname>" -ForegroundColor Gray
Write-Host "  2. Add hosts to LibreNMS monitoring" -ForegroundColor Gray
Write-Host "  3. Verify WMI-SNMP provider is working (check LibreNMS for Windows-specific OIDs)" -ForegroundColor Gray
Write-Host "  4. Run cleanup script to scrub community string from C:\Windows\Temp\snmpcap.ps1" -ForegroundColor Gray