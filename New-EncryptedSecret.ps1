#requires -Version 7.0

<#
.SYNOPSIS
    Create encrypted SNMP community string for deployment
.NOTES
    Uses Windows DPAPI - only decryptable by the same user on the same machine
    For production: migrate to Azure Key Vault or HashiCorp Vault
#>

param(
    [Parameter(Mandatory)]
    [string]$OutputPath = ".\secrets\snmp-community.enc"
)

$ErrorActionPreference = 'Stop'

# Ensure output directory exists
$outputDir = Split-Path $OutputPath -Parent
if ($outputDir -and -not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

# Prompt for community string securely
$secure = Read-Host -Prompt "Enter SNMP Community String" -AsSecureString

# Convert to encrypted standard string (DPAPI)
$encrypted = ConvertFrom-SecureString -SecureString $secure

# Save to file (no newlines)
$encrypted | Set-Content $OutputPath -NoNewline

Write-Host "`n[+] Encrypted secret saved to: $OutputPath" -ForegroundColor Green
Write-Host "[!] This file can only be decrypted by: $env:USERNAME on $env:COMPUTERNAME" -ForegroundColor Yellow
Write-Host "[!] For production: migrate to Azure Key Vault or HashiCorp Vault" -ForegroundColor Yellow

# Verify it works
try {
    $testSecure = ConvertTo-SecureString (Get-Content $OutputPath)
    $testPlain = [System.Net.NetworkCredential]::new('', $testSecure).Password
    Write-Host "[+] Verification successful - secret is decryptable" -ForegroundColor Green
}
catch {
    Write-Host "[X] Verification failed: $_" -ForegroundColor Red
    exit 1
}