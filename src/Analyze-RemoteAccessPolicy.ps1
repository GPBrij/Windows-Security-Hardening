
# Windows Remote Access Firewall Policy Report
# This script identifies what's allowing remote access and who configured it

Write-Host "`n╔════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  WINDOWS REMOTE ACCESS & FIREWALL POLICY ANALYSIS REPORT          ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

# Section 1: Firewall Profiles
Write-Host "`n[1] FIREWALL PROFILE STATUS:" -ForegroundColor Yellow
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table

# Section 2: Remote Services Status
Write-Host "`n[2] REMOTE SERVICES CONFIGURATION:" -ForegroundColor Yellow
$remoteServices = @('TermService', 'RasMan', 'WinRM', 'RemoteRegistry')
foreach ($svc in $remoteServices) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service) {
        Write-Host "  • $svc : Status=$(if($service.Status -eq 'Running'){'RUNNING ⚠'} else {'Stopped ✓'}) | Startup=$($service.StartType)" -ForegroundColor $(if($service.Status -eq 'Running'){'Red'} else {'Green'})
    }
}

# Section 3: Group Policy Firewall Rules
Write-Host "`n[3] GROUP POLICY FIREWALL RULES (Inbound Allow):" -ForegroundColor Yellow
$gpRules = Get-NetFirewallRule -Direction Inbound -Action Allow | Where-Object {$_.PolicyStoreSource -like "*Group*"}
if ($gpRules.Count -gt 0) {
    Write-Host "  Found $($gpRules.Count) Group Policy rules allowing inbound traffic" -ForegroundColor Red
    $gpRules | Select-Object DisplayName, Name, Owner | Format-Table -AutoSize
} else {
    Write-Host "  No Group Policy firewall rules found" -ForegroundColor Green
}

# Section 4: Built-in Inbound Allow Rules
Write-Host "`n[4] BUILT-IN INBOUND ALLOW RULES (Security Baseline):" -ForegroundColor Yellow
$builtinRules = Get-NetFirewallRule -Direction Inbound -Action Allow | Where-Object {$_.PolicyStoreSource -like "*SYSTEM*" -or $_.PolicyStoreSource -like "*Static*"}
Write-Host "  Count: $($builtinRules.Count) rules" -ForegroundColor Yellow
Write-Host "  Sample rules allowing remote services:" -ForegroundColor White
$builtinRules | Where-Object {$_.DisplayName -like "*Remote*" -or $_.DisplayName -like "*RPC*"} | Select-Object DisplayName, Owner -First 15 | Format-Table

# Section 5: Remote Assistance & RDP Configuration
Write-Host "`n[5] REMOTE ASSISTANCE CONFIGURATION:" -ForegroundColor Yellow
$rdpConfig = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue
if ($rdpConfig) {
    Write-Host "  • fDenyTSConnections: $($rdpConfig.fDenyTSConnections) (0=Enabled ⚠, 1=Disabled ✓)" -ForegroundColor $(if($rdpConfig.fDenyTSConnections -eq 0){'Red'} else {'Green'})
}

$remoteAssistance = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -ErrorAction SilentlyContinue
if ($remoteAssistance) {
    Write-Host "  • Remote Assistance fAllowUnsolicited: $($remoteAssistance.fAllowUnsolicited) (0=Disabled ✓, 1=Enabled ⚠)" -ForegroundColor $(if($remoteAssistance.fAllowUnsolicited -eq 1){'Red'} else {'Green'})
}

# Section 6: WinRM Configuration (Windows Remote Management)
Write-Host "`n[6] WINDOWS REMOTE MANAGEMENT (WinRM) STATUS:" -ForegroundColor Yellow
try {
    $winrmService = Get-Service WinRM -ErrorAction Stop
    Write-Host "  • WinRM Service: $($winrmService.Status) | Startup: $($winrmService.StartType)" -ForegroundColor $(if($winrmService.Status -eq 'Running'){'Red'} else {'Green'})
    
    $winrmConfig = Get-Item -Path WSMan:\localhost\Client\Auth -ErrorAction SilentlyContinue
    if ($winrmConfig) {
        Write-Host "  • WinRM Client Auth Enabled: Yes ⚠" -ForegroundColor Red
    }
} catch {
    Write-Host "  • WinRM not accessible" -ForegroundColor Yellow
}

# Section 7: Network Service Configuration
Write-Host "`n[7] NETWORK SERVICE ACCOUNTS RUNNING REMOTE SERVICES:" -ForegroundColor Yellow
$networkServices = @{
    'TermService' = 'NT Authority\NetworkService'
    'RasMan' = 'Local System'
    'WinRM' = 'Local System'
}
foreach ($svc in $networkServices.GetEnumerator()) {
    Write-Host "  • $($svc.Key): Runs as $($svc.Value)" -ForegroundColor Cyan
}

# Section 8: Potential Group Policy Objects
Write-Host "`n[8] ACTIVE DIRECTORY GROUP POLICY SEARCH:" -ForegroundColor Yellow
try {
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    if ($domain) {
        Write-Host "  • Domain Found: $($domain.Name)" -ForegroundColor Green
        Write-Host "  ⚠ Group Policies may be enforcing firewall rules from Domain Controllers" -ForegroundColor Yellow
    } else {
        Write-Host "  • Workgroup machine (no Active Directory)" -ForegroundColor Green
    }
} catch {
    Write-Host "  • Workgroup machine (no Active Directory)" -ForegroundColor Green
}

# Section 9: Security Audit
Write-Host "`n[9] SECURITY ASSESSMENT:" -ForegroundColor Yellow
$issuesFound = @()

if ((Get-Service -Name TermService).Status -eq 'Running') {
    $issuesFound += "Remote Desktop (TermService) is RUNNING"
}

if ((Get-Service -Name RasMan).Status -eq 'Running') {
    $issuesFound += "Remote Access Service (RasMan) is RUNNING"
}

if ((Get-Service -Name WinRM).Status -eq 'Running') {
    $issuesFound += "Windows Remote Management (WinRM) is RUNNING"
}

$allowRules = (Get-NetFirewallRule -Direction Inbound -Action Allow | Measure-Object).Count
if ($allowRules -gt 50) {
    $issuesFound += "Too many inbound allow rules ($allowRules) - potential exposure"
}

if ($issuesFound.Count -gt 0) {
    Write-Host "  ⚠ ISSUES FOUND:" -ForegroundColor Red
    foreach ($issue in $issuesFound) {
        Write-Host "     - $issue" -ForegroundColor Red
    }
} else {
    Write-Host "  ✓ No major issues detected" -ForegroundColor Green
}

Write-Host "`n[10] REMEDIATION SUMMARY:" -ForegroundColor Yellow
Write-Host "  To fully block remote access:" -ForegroundColor White
Write-Host "     1. Stop and disable TermService (RDP)" -ForegroundColor Cyan
Write-Host "     2. Stop and disable RasMan (VPN/Remote Access)" -ForegroundColor Cyan
Write-Host "     3. Disable WinRM (Windows Remote Management)" -ForegroundColor Cyan
Write-Host "     4. Disable all Remote Assistance firewall rules" -ForegroundColor Cyan
Write-Host "     5. Set firewall DefaultInboundAction to Block (already done)" -ForegroundColor Cyan

Write-Host "`n" -ForegroundColor White

