#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [int]$LastHours = 2,
    [switch]$DebugMode = $false
)

$ErrorActionPreference = 'Stop'

$blacklistFile = Join-Path $PSScriptRoot 'blacklist.txt'
$blockedFile = Join-Path $PSScriptRoot 'blocked.txt'
$whitelistFile = Join-Path $PSScriptRoot 'whitelist.txt'
$changeLogFile = Join-Path $PSScriptRoot 'blocked-changes.log'

function Get-FailedIps {
    # Get IP addresses with more than 10 failed Windows logon attempts
    $extraParams = @{}
    if ($LastHours -gt 0) {
        $extraParams.LastHours = $LastHours
    }

    $getFailedLogons = Join-Path $PSScriptRoot 'Get-FailedLogons.ps1'

    & $getFailedLogons @extraParams |
        ForEach-Object {
            $_.Name
        } |
        Where-Object { $_ } |
        Select-Object -Unique
}

function Get-FailedIpsOpenSSH {
    # Get IP addresses with more than 10 failed Windows logon attempts
    $extraParams = @{}
    if ($LastHours -gt 0) {
        $extraParams.LastHours = $LastHours
    }

    $getFailedLogons = Join-Path $PSScriptRoot 'Get-FailedLogons_OpenSSH.ps1'

    & $getFailedLogons @extraParams |
        ForEach-Object {
            $_.Name
        } |
        Where-Object { $_ } |
        Select-Object -Unique
}

function Get-FailedIpsSql {
    $extraParams = @{
        ServerInstance = ".\SQLEXPRESS"
        MinCount       = 10
    }

    if ($LastHours -gt 0) {
        $extraParams.LastHours = $LastHours
    }

    $getFailedLogons = Join-Path $PSScriptRoot 'Get-FailedLogons_MSSQL.ps1'

    & $getFailedLogons @extraParams |
        Select-Object -ExpandProperty IPAddress |
        Where-Object { $_ } |
        Select-Object -Unique
}

function Get-BlacklistedIps {
    Get-Content -Path $blacklistFile -Encoding Ascii -ErrorAction SilentlyContinue |
        Where-Object { $_ } |
        Select-Object -Unique
}

function Get-BlockedIps {
    Get-Content -Path $blockedFile -Encoding Ascii -ErrorAction SilentlyContinue |
        Where-Object { $_ } |
        Select-Object -Unique
}

function Get-AllowedIps {
    Get-Content -Path $whitelistFile -Encoding Ascii -ErrorAction SilentlyContinue |
        Where-Object { $_ } |
        Select-Object -Unique
}

function Write-BlacklistChanges {
    param(
        [AllowNull()]
        [string[]]$OldIps,

        [AllowNull()]
        [string[]]$NewIps
    )

    $oldList = @($OldIps | Where-Object { $_ })
    $newList = @($NewIps | Where-Object { $_ })

    $changes = Compare-Object -ReferenceObject $oldList -DifferenceObject $newList

    if (-not $changes) {
        return
    }

    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ssK')

    $logLines = foreach ($change in $changes) {
        $action = switch ($change.SideIndicator) {
            '=>' { 'Added' }
            '<=' { 'Removed' }
            default { 'Unknown' }
        }

        '{0};{1};{2}' -f $timestamp, $change.InputObject, $action
    }

    $logLines | Add-Content -Path $changeLogFile -Encoding UTF8
}

#
# Main
#

$failedIps = @(Get-FailedIps)
$failedIpsSql = @(Get-FailedIpsSql)
$failedIpsOpenSSH = @(Get-FailedIpsOpenSSH)
$blacklistedIps = @(Get-BlacklistedIps)
$oldBlockedIps = @(Get-BlockedIps)

$newBlockedIps = @(
    [array]$failedIps + [array]$failedIpsSql + [array]$failedIpsOpenSSH + [array]$blacklistedIps
) |
    Where-Object { $_ } |
    Select-Object -Unique |
    Sort-Object

Write-BlacklistChanges -OldIps $oldBlockedIps -NewIps $newBlockedIps

$newBlockedIps | Out-File -FilePath $blockedFile -Encoding ascii

$allowedIps = @(Get-AllowedIps)
$firewallIps = @(
    $newBlockedIps | Where-Object { $_ -notin $allowedIps }
)

$ruleName = 'PSFail2Ban-Block-Failed-Logons'
$ruleDisplayName = 'PSFail2Ban: Blocks IP addresses from failed logons'
$existingRule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue

if ($DebugMode) {
    Write-Host 'DEBUG MODE ACTIVE - Firewall will not be updated.' -ForegroundColor Yellow
    Write-Host "Rule Name: $ruleName"

    if ($existingRule) {
        Write-Host 'Existing Firewall Rule: Yes'
    }
    else {
        Write-Host 'Existing Firewall Rule: No'
    }

    Write-Host "Number of IPs after whitelist filter: $($firewallIps.Count)"

    if ($firewallIps.Count -gt 0) {
        Write-Host 'The following IPs would be set in the firewall:'
        $firewallIps | ForEach-Object { Write-Host "  $_" }
    }
    else {
        Write-Host 'There are no IPs to block.'
        if ($existingRule) {
            Write-Host 'The existing firewall rule would be removed.'
        }
        else {
            Write-Host 'There is no existing firewall rule, no action would be needed.'
        }
    }

    return
}

if ($firewallIps.Count -gt 0) {
    if ($existingRule) {
        Set-NetFirewallRule -Name $ruleName -RemoteAddress $firewallIps
    }
    else {
        New-NetFirewallRule `
            -Name $ruleName `
            -DisplayName $ruleDisplayName `
            -Direction Inbound `
            -Action Block `
            -RemoteAddress $firewallIps
    }
}
else {
    if ($existingRule) {
        Remove-NetFirewallRule -Name $ruleName
    }
}