# SQLServer Module is optional and only needed if you want to monitor sql server logs. 
# If you don't have it installed, the script will still work but won't be able to monitor sql server logs.

Install-Module -Name SqlServer -AllowClobber -Force -Scope AllUsers


$commandToRun = Join-Path $PSScriptRoot 'Update-FirewallRule.cmd'

& schtasks.exe /create /tn "PSFail2Ban - Update firewall rules" /sc MINUTE /mo 5 /st 00:00 /f /ru "System" /tr $commandToRun
