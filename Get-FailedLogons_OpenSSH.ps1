# Checks the OpenSSH/Operational event log for failed SSH logon attempts 
# and returns the source IP addresses or usernames with more than a specified 
# number of failed attempts within a given time frame.

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [int]$LastHours = 1,
    [Switch]$ShowUsernames = $false,
    [int]$MinCount = 10
)

$ErrorActionPreference = 'Stop'

#
# Returns the number of failed SSH logon attempts for each source IP address
# or username, depending on -ShowUsernames.
#

$filters = @{
    LogName = "OpenSSH/Operational"
    Id      = 4
}

if ($LastHours -gt 0) {
    $filters.StartTime = (Get-Date).AddHours(-$LastHours)
}

$events = @(
    Get-WinEvent -FilterHashTable $filters -ErrorAction SilentlyContinue
)

if (-not $events -or $events.Count -eq 0) {
    return @()
}

$events |
ForEach-Object {
    try {
        $xml = [xml]$_.ToXml()

        $payloadNode = $xml.Event.EventData.Data |
        Where-Object { $_.Name -eq 'payload' } |
        Select-Object -First 1

        if (-not $payloadNode) {
            return
        }

        $payload = [string]$payloadNode.'#text'

        if ([string]::IsNullOrWhiteSpace($payload)) {
            return
        }

        if ($payload -notmatch 'Failed password') {
            return
        }

        # Examples:
        # Failed password for invalid user WebDeploy from 78.94.96.58 port 16279 ssh2
        # Failed password for root from 2001:db8::1 port 2222 ssh2
        if ($payload -match '^Failed password for (?:invalid user )?(?<User>\S+) from (?<IP>[0-9A-Fa-f:.%]+) port \d+') {
            $user = $Matches['User']
            $ip = $Matches['IP']

            # IP additionally validate (IPv4 or IPv6)
            $parsedIp = $null
            if ([System.Net.IPAddress]::TryParse($ip, [ref]$parsedIp)) {
                if ($ShowUsernames) {
                    $user
                }
                else {
                    $ip
                }
            }
        }
    }
    catch {
        # Ignore individual faulty events to allow the rest to continue
    }
} |
Where-Object { $_ -and $_ -ne '-' } |
Group-Object -NoElement |
Where-Object { $_.Count -gt $MinCount } |
Sort-Object -Property Count -Descending