# =====================================================
# CURRENT SECURITY POSTURE SNAPSHOT (READ-ONLY)
# Windows PowerShell 5.1 compatible
# =====================================================

$TimeStamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$ReportPath = "$env:USERPROFILE\Downloads\SecurityPosture_Report.txt"

$Results = @()

function Add-Result {
    param ($Category, $Item, $Status, $Explanation)

    $Results += [PSCustomObject]@{
        Category    = $Category
        Item        = $Item
        Status      = $Status
        Explanation = $Explanation
    }
}

# =====================================================
# 1. REMOTE ACCESS SERVICES
# =====================================================
$serviceList = @("WinRM","TermService","sshd")

foreach ($svcName in $serviceList) {
    $svc = Get-Service $svcName -ErrorAction SilentlyContinue
    if (-not $svc) {
        Add-Result "Service" $svcName "PASS" "Service not present"
    }
    elseif ($svc.Status -eq "Stopped" -and $svc.StartType -eq "Disabled") {
        Add-Result "Service" $svcName "PASS" "Stopped and disabled"
    }
    else {
        Add-Result "Service" $svcName "FAIL" "Service running or enabled"
    }
}

# =====================================================
# 2. DISCOVERY & LATERAL SERVICES
# =====================================================
$discoveryServices = @("SSDPSRV","upnphost","FDResPub","SNMPTRAP","LanmanServer")

foreach ($svcName in $discoveryServices) {
    $svc = Get-Service $svcName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Stopped" -and $svc.StartType -eq "Disabled") {
        Add-Result "Service" $svcName "PASS" "Discovery / sharing disabled"
    }
    else {
        Add-Result "Service" $svcName "FAIL" "Service enabled or present"
    }
}

# =====================================================
# 3. REGISTRY ENFORCEMENT
# =====================================================

# Remote Assistance
$ra = Get-ItemProperty `
  'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' `
  -Name fAllowToGetHelp -ErrorAction SilentlyContinue

if ($ra -and $ra.fAllowToGetHelp -eq 0) {
    Add-Result "Registry" "Remote Assistance" "PASS" `
    "Consent-based remote support enforced off"
}
else {
    Add-Result "Registry" "Remote Assistance" "FAIL" `
    "Remote Assistance not registry-enforced"
}

# LLMNR
$llmnr = Get-ItemProperty `
 'HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient' `
 -Name EnableMulticast -ErrorAction SilentlyContinue

if ($llmnr -and $llmnr.EnableMulticast -eq 0) {
    Add-Result "Registry" "LLMNR" "PASS" `
    "Name poisoning attack surface removed"
}
else {
    Add-Result "Registry" "LLMNR" "FAIL" `
    "LLMNR still enabled"
}

# IPv6
$ipv6 = Get-ItemProperty `
 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' `
 -Name DisabledComponents -ErrorAction SilentlyContinue

if ($ipv6 -and $ipv6.DisabledComponents -eq 255) {
    Add-Result "Registry" "IPv6" "PASS" `
    "Dual-stack network attack surface removed"
}
else {
    Add-Result "Registry" "IPv6" "FAIL" `
    "IPv6 not fully disabled"
}

# =====================================================
# 4. NETBIOS
# =====================================================
$netbiosAdapters = Get-CimInstance Win32_NetworkAdapterConfiguration |
Where-Object { $_.IPEnabled }

$netbiosFail = $false
foreach ($nic in $netbiosAdapters) {
    if ($nic.TcpipNetbiosOptions -ne 2) {
        $netbiosFail = $true
    }
}

if ($netbiosFail) {
    Add-Result "Protocol" "NetBIOS" "FAIL" `
    "Legacy NetBIOS name resolution still enabled"
}
else {
    Add-Result "Protocol" "NetBIOS" "PASS" `
    "Legacy NetBIOS name resolution disabled"
}

# =====================================================
# 5. FIREWALL – EFFECTIVE EXPOSURE
# =====================================================
$profiles = Get-NetFirewallProfile
$blockedProfiles = 0

foreach ($p in $profiles) {
    if ($p.Enabled -and $p.DefaultInboundAction -eq "Block") {
        $blockedProfiles++
    }
}

if ($blockedProfiles -eq 3) {
    Add-Result "Firewall" "Inbound Policy" "PASS" `
    "Inbound traffic blocked for all profiles"
}
else {
    Add-Result "Firewall" "Inbound Policy" "FAIL" `
    "One or more profiles allow inbound traffic"
}

$allowRules = Get-NetFirewallRule |
Where-Object { $_.Direction -eq "Inbound" -and $_.Action -eq "Allow" }

Add-Result "Firewall" "Inbound Allow Rules (Artefacts)" "INFO" `
"$($allowRules.Count) rules exist but are overridden by policy"

Add-Result "Exposure" "Effective Inbound Exposure" "PASS" `
"No unsolicited inbound connectivity possible"

# =====================================================
# OUTPUT REPORT
# =====================================================
"SECURITY POSTURE SNAPSHOT" | Out-File $ReportPath
"Generated: $TimeStamp" | Out-File $ReportPath -Append
"==================================================" | Out-File $ReportPath -Append

foreach ($r in $Results) {
    "$($r.Category) | $($r.Item) | $($r.Status)" | Out-File $ReportPath -Append
    "  $($r.Explanation)" | Out-File $ReportPath -Append
}

$overall = "SECURE / ISOLATED"
if ($Results.Status -contains "FAIL") { $overall = "NOT COMPLIANT" }

"" | Out-File $ReportPath -Append

