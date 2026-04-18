# PSFail2Ban

Powershell script to block IP addresses after multiple failed logon attempts.



## How to install

Download all scripts in any folder and run (with administrative privileges):

```powershell
Install-ScheduledTask.ps1
```

This will create a scheduled task to run `Update-FirewallRule.ps1` (see below) every 5 minutes.

## Enabling Event ID 4625 in Windows Security Logs

To enable Event ID 4625 (Failed Logon) in the Windows Security Logs, follow these steps:

1. Open the **Group Policy Editor**:
   - Press `Win + R`, type `gpedit.msc`, and press Enter.

2. Navigate to the following path:
   - `Computer Configuration` → `Windows Settings` → `Security Settings` → `Advanced Audit Policy Configuration` → `Audit Policies` → `Logon/Logoff`.

3. Enable the policy:
   - Double-click on **Audit Logon**.
   - Check **Failure** to log failed logon attempts.
   - Click **OK** to save the changes.

4. Apply the policy:
   - Run `gpupdate /force` in an elevated Command Prompt to apply the changes immediately.

Once enabled, Event ID 4625 will appear in the Windows Security Logs for failed logon attempts.

## How it works

The main script is `Update-FirewallRule.ps1`. It checks for Event ID 4625 entries in Windows Security logs and adds a blocking rule in Windows Firewall for every IP address with 10 or more failed logons.

Also, all blocked IPs will be saved in a `blacklist.txt`. You can change this file if needed. Addresses in this file will ALWAYS be blocked by the firewall rule even if they didn't show up in Security events.

In the same way, you could keep a `whitelist.txt`. Addresses in this file will NEVER be blocked by the firewall rule.

By default the script will check only the last 1 hours in Security log. You can use the `-LastHours` parameter to change this number.



## Other tools

If you want a quick summary of failed logins, just run

```powershell
Get-FailedLogons.ps1
```

This will show the number of failed logons attempts for each source IP address.

Alternatively, you can run it with `-ShowUsernames` parameter

```powershell
Get-FailedLogons.ps1 -ShowUsernames
```

which will show the same result but now grouped by usernames.

By default the script will check only the last 6 hours in Security log. You can use the `-LastHours` parameter to change this number.



