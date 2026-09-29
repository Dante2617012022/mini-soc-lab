[CmdletBinding()]
param(
    [switch]$Help
)

if ($Help) {
    @'
Usage:
  powershell -ExecutionPolicy Bypass -File .\scripts\management\collect-windows-host-capacity.ps1

Read-only capacity inventory for the Windows host that will run SOC-MGMT-01.
The script does not change system configuration and does not write files.
It intentionally avoids printing IP addresses, MAC addresses, usernames, or secrets.
'@
    exit 0
}

$ErrorActionPreference = 'Stop'

function Write-Section {
    param([Parameter(Mandatory)][string]$Name)
    Write-Host ""
    Write-Host "=== $Name ==="
}

Write-Host "MINI-SOC SOC-MGMT-01 HOST CAPACITY CHECK"
Write-Host "Mode: read-only"

Write-Section "WINDOWS"
Get-ComputerInfo |
    Select-Object WindowsProductName, WindowsVersion, OsArchitecture

Write-Section "CPU"
Get-CimInstance Win32_Processor |
    Select-Object Name,
        NumberOfCores,
        NumberOfLogicalProcessors,
        VirtualizationFirmwareEnabled

Write-Section "MEMORY"
Get-CimInstance Win32_ComputerSystem |
    Select-Object @{
        Name = 'RAM_GB'
        Expression = { [math]::Round($_.TotalPhysicalMemory / 1GB, 2) }
    }, HypervisorPresent

Write-Section "FILESYSTEM CAPACITY"
Get-PSDrive -PSProvider FileSystem |
    Where-Object { $_.Used -ne $null -and $_.Free -ne $null } |
    Select-Object Name,
        @{
            Name = 'Used_GB'
            Expression = { [math]::Round($_.Used / 1GB, 2) }
        },
        @{
            Name = 'Free_GB'
            Expression = { [math]::Round($_.Free / 1GB, 2) }
        }

Write-Section "ACTIVE NETWORK ADAPTERS"
Get-NetAdapter |
    Where-Object Status -eq 'Up' |
    Select-Object Name, InterfaceDescription, Status, LinkSpeed

Write-Section "VIRTUALBOX"
$defaultVBoxManage = 'C:\Program Files\Oracle\VirtualBox\VBoxManage.exe'
$vbox = Get-Command VBoxManage.exe -ErrorAction SilentlyContinue

if ($vbox) {
    Write-Host "VBoxManage: $($vbox.Source)"
    & $vbox.Source --version
}
elseif (Test-Path $defaultVBoxManage) {
    Write-Host "VBoxManage: $defaultVBoxManage"
    & $defaultVBoxManage --version
}
else {
    Write-Warning "VBoxManage.exe was not found in PATH or the default install path."
}

Write-Section "SUMMARY"
Write-Host "No system configuration was changed."
Write-Host "Review CPU, RAM and free disk before creating SOC-MGMT-01."
