# Returns failed logon attempts from SQL Server error logs, 
# grouped by username or IP address. With more than MinCount attempts, 
# it can indicate potential brute-force attacks or misconfigurations. 
# The script reads multiple error logs (up to MaxErrorLogs) to gather a 
# comprehensive view of failed logins within the specified time frame (LastHours). 
# It uses regex patterns to extract relevant information and filter out non-relevant 
# log entries based on the reason for failure. DebugOutput can be enabled for detailed 
# analysis of each log entry.

#Requires -Modules SqlServer

[CmdletBinding()]
param(
    [string]$ServerInstance = ".\SQLEXPRESS",
    [int]$LastHours = 1,
    [switch]$ShowUsernames = $false,
    [int]$MinCount = 10,
    [int]$MaxErrorLogs = 0,
    [switch]$DebugOutput = $false
)

$ErrorActionPreference = 'Stop'

Import-Module SqlServer

$startTime = if ($LastHours -gt 0) {
    (Get-Date).AddHours(-$LastHours)
}
else {
    $null
}

$userRegex   = [regex]"Login failed for user '(?<User>[^']+)'\."
$clientRegex = [regex]"\[CLIENT:\s*(?<IP>[^\]]+)\]"
$reasonRegex = [regex]"(?:Ursache|Reason):\s*(?<Reason>.*?)(?=\s*\[CLIENT:|$)"

# Should trigger:
# - User/Login does not exist
# - Incorrect password
$allowedReasonPatterns = @(
    'Es konnte keine Anmeldung gefunden werden, die mit dem angegebenen Namen übereinstimmt',
    'login matching the name provided',
    'Kennwort',
    'Passwort',
    'password',
    'password did not match',
    'invalid password',
    'falsches Kennwort',
    'falsches Passwort',
    'Es konnte keine Anmeldung gefunden werden'
)

# Should NOT trigger:
# - DB does not exist / Default DB not reachable / similar DB issues
$blockedReasonPatterns = @(
    'Datenbank',
    'database',
    'default database',
    'Standarddatenbank',
    'Cannot open',
    'kann nicht geöffnet',
    'nicht geöffnet werden',
    'Fehler beim Öffnen'
)

$invokeParams = @{
    ServerInstance         = $ServerInstance
    TrustServerCertificate = $true
    Encrypt                = 'Optional'
    ErrorAction            = 'Stop'
}

$allRows = New-Object System.Collections.Generic.List[object]

foreach ($logNumber in 0..$MaxErrorLogs) {
    try {
        $query = "EXEC master.dbo.sp_readerrorlog $logNumber, 1, N'Login failed for user';"
        $rows = Invoke-Sqlcmd @invokeParams -Query $query

        foreach ($row in $rows) {
            $allRows.Add($row)
        }
    }
    catch {
        Write-Verbose "Could not read SQL error log $logNumber : $($_.Exception.Message)"
    }
}

$parsedRows = foreach ($row in $allRows) {
    $logDate = $row.LogDate
    $process = $row.ProcessInfo
    $text    = [string]$row.Text

    $isInTimeRange = (-not $startTime -or $logDate -ge $startTime)
    $isLogonEvent  = ($process -eq 'Logon')

    $userMatch   = $userRegex.Match($text)
    $clientMatch = $clientRegex.Match($text)
    $reasonMatch = $reasonRegex.Match($text)

    $username = if ($userMatch.Success) { $userMatch.Groups['User'].Value.Trim() } else { $null }
    $ip       = if ($clientMatch.Success) { $clientMatch.Groups['IP'].Value.Trim() } else { $null }
    $reason   = if ($reasonMatch.Success) { $reasonMatch.Groups['Reason'].Value.Trim().TrimEnd('.') } else { $null }

    $matchedAllowedPattern = $null
    $matchedBlockedPattern = $null

    if ($reason) {
        foreach ($pattern in $allowedReasonPatterns) {
            if ($reason -match $pattern) {
                $matchedAllowedPattern = $pattern
                break
            }
        }

        foreach ($pattern in $blockedReasonPatterns) {
            if ($reason -match $pattern) {
                $matchedBlockedPattern = $pattern
                break
            }
        }
    }

    $reasonAllowed = [bool]$matchedAllowedPattern
    $reasonBlocked = [bool]$matchedBlockedPattern

    $wouldTrigger =
        $isLogonEvent -and
        $isInTimeRange -and
        $userMatch.Success -and
        $clientMatch.Success -and
        $reasonAllowed -and
        (-not $reasonBlocked)

    [pscustomobject]@{
        LogDate               = $logDate
        ProcessInfo           = $process
        InTimeRange           = $isInTimeRange
        UserMatched           = $userMatch.Success
        ClientMatched         = $clientMatch.Success
        ReasonMatched         = $reasonMatch.Success
        Username              = $username
        IPAddress             = $ip
        Reason                = $reason
        ReasonAllowed         = $reasonAllowed
        ReasonBlocked         = $reasonBlocked
        AllowedPattern        = $matchedAllowedPattern
        BlockedPattern        = $matchedBlockedPattern
        WouldTrigger          = $wouldTrigger
        Text                  = $text
    }
}

if ($DebugOutput) {
    $parsedRows |
        Sort-Object LogDate -Descending |
        Select-Object `
            LogDate,
            ProcessInfo,
            InTimeRange,
            UserMatched,
            ClientMatched,
            ReasonMatched,
            Username,
            IPAddress,
            ReasonAllowed,
            ReasonBlocked,
            AllowedPattern,
            BlockedPattern,
            WouldTrigger,
            Reason,
            Text
    return
}

$resultLabel = if ($ShowUsernames) { 'Username' } else { 'IPAddress' }

$parsedRows |
    Where-Object {
        $_.WouldTrigger -and
        $_.Username -and
        $_.IPAddress -and
        $_.IPAddress -ne '-' -and
        $_.IPAddress -ne '(local)'
    } |
    ForEach-Object {
        [pscustomobject]@{
            LogDate   = $_.LogDate
            Username  = $_.Username
            IPAddress = $_.IPAddress
            Reason    = $_.Reason
            Key       = if ($ShowUsernames) { $_.Username } else { $_.IPAddress }
        }
    } |
    Group-Object -Property Key |
    Where-Object { $_.Count -gt $MinCount } |
    Sort-Object Count -Descending |
    Select-Object Count, @{Name = $resultLabel; Expression = { $_.Name } }