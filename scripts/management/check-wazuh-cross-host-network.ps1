param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('ManagerHost', 'EndpointHost')]
    [string]$Role,

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^(?:\d{1,3}\.){3}\d{1,3}$')]
    [string]$ManagerAddress
)

$ErrorActionPreference = 'Stop'

Write-Host 'MINI-SOC WAZUH CROSS-HOST NETWORK CHECK'
Write-Host "Role: $Role"
Write-Host 'Mode: read-only'
Write-Host ''

$profiles = @{}
Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object {
    $profiles[$_.InterfaceAlias] = $_
}

$candidates = Get-NetIPConfiguration | Where-Object {
    $_.NetAdapter.Status -eq 'Up' -and $_.IPv4Address
} | ForEach-Object {
    foreach ($address in $_.IPv4Address) {
        if ($address.IPAddress -notmatch '^127\.' -and $address.IPAddress -notmatch '^169\.254\.') {
            $profile = $profiles[$_.InterfaceAlias]
            [pscustomobject]@{
                InterfaceAlias  = $_.InterfaceAlias
                IPv4Address     = $address.IPAddress
                PrefixLength    = $address.PrefixLength
                DefaultGateway  = ($_.IPv4DefaultGateway.NextHop -join ',')
                NetworkCategory = if ($profile) { $profile.NetworkCategory } else { 'Unknown' }
                Connectivity    = if ($profile) { $profile.IPv4Connectivity } else { 'Unknown' }
            }
        }
    }
}

Write-Host 'Active IPv4 candidates:'
if ($candidates) {
    $candidates | Format-Table -AutoSize
} else {
    Write-Host 'NONE'
}

Write-Host ''
Write-Host 'Windows Firewall profiles:'
Get-NetFirewallProfile |
    Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction |
    Format-Table -AutoSize

if ($Role -eq 'ManagerHost') {
    Write-Host ''
    Write-Host 'Host listener conflicts for Wazuh-related ports:'
    $listenerState = foreach ($port in 1514, 1515, 443, 55000, 9200) {
        $listener = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue
        [pscustomobject]@{
            Port      = $port
            Listening = [bool]$listener
        }
    }
    $listenerState | Format-Table -AutoSize
}

if ($ManagerAddress) {
    Write-Host ''
    Write-Host "Reachability to manager address $ManagerAddress:"
    $reachability = foreach ($port in 1514, 1515) {
        $result = Test-NetConnection -ComputerName $ManagerAddress -Port $port -WarningAction SilentlyContinue
        [pscustomobject]@{
            Port             = $port
            TcpTestSucceeded = $result.TcpTestSucceeded
        }
    }
    $reachability | Format-Table -AutoSize
}

Write-Host ''
Write-Host 'No configuration changes were made.'
