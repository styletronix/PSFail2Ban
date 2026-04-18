# check for failed logon attempts in the Security event log (Event ID 4625)

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [int]$LastHours = 1,
    [Switch]$ShowUsernames = $false,
    [int]$MinCount = 10
)

$ErrorActionPreference = 'Stop'

#
# Returns the number of failed logon attempts for each source IP address or username, depending on -ShowUsernames.
#

$filters = @{
    LogName = "Security"
    Id      = 4625
}

if ($LastHours -gt 0) {
    $filters.StartTime = (Get-Date).AddHours(-$LastHours)
}

if ($ShowUsernames) {
    $propertyIndex = 5   # Username
}
else {
    $propertyIndex = 19  # Source IP
}

$events = @(
    Get-WinEvent -FilterHashTable $filters -ErrorAction SilentlyContinue
)

if (-not $events -or $events.Count -eq 0) {
    return @()
}

$events |
    ForEach-Object {
        if ($_.Properties.Count -gt $propertyIndex) {
            $_.Properties[$propertyIndex].Value
        }
    } |
    Where-Object { $_ -and $_ -ne '-' } |
    Group-Object -NoElement |
    Where-Object { $_.Count -gt $MinCount } |
    Sort-Object -Property Count -Descending