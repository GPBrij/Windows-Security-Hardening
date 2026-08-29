# =====================================================
# Verify-RemoteAccessLockdown_WithRecommendations.ps1
# Governance-grade verification + recommendations
# =====================================================

$TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$ReportPath = "$env:USERPROFILE\Downloads\RemoteAccessLockdown_Report.txt"

$Results = @()
$Recommendations = @()

function Add-Result {
    param (
        [string]$Control,
        [string]$Status,
        [string]$Details
    )

    $Results += [PSCustomObject]@{
        Control = $Control
        Status  = $Status
        Details = $Details
    }
}

function Add-Recommendation {
    param (
        [string]$Control,
        [string]$Recommendation,
        [string]$Rationale
    )

    $Recommendations += [PSCustomObject]@{
        Control        = $Control
        Recommendation = $Recommendation
        Rationale      = $Rationale
    }
}

Write-Host "=== Remote Access Lockdown Verification ==="
Write-Host "Date: $TimeStamp"
Write-Host ""

# =====================================================
# 1. WinRM / PowerShell Remoting
# =====================================================
$winrm = Get-Service WinRM -ErrorAction SilentlyContinue

if ($winrm.Status -eq 'Stopped' -and $winrm.StartType -eq 'Disabled') {
    Add-Result "PowerShell Remoting (WinRM)" "PASS" "Service stopped and disabled"
} else {
    Add-Result "PowerShell Remoting (WinRM)" "FAIL" "$($winrm.Status), $($winrm.StartType)"
    Add-Recommendation `
        "PowerShell Remoting (WinRM)" `
        "Disable WinRM service permanently" `
        "WinRM enables remote command execution and should be disabled on local-only workstations."
}

# =====================================================
# 2. Remote Desktop Services
# =====================================================
$rds = Get-Service TermService -ErrorAction SilentlyContinue

if ($rds.Status -eq 'Stopped' -and $rds.StartType -eq 'Disabled') {
    Add-Result "Remote Desktop Services (RDP backend)" "PASS" "Service stopped and disabled"
} else {
    Add-Result "Remote Desktop Services (RDP backend)" "FAIL" "$($rds.Status), $($rds.StartType)"
    Add-Recommendation `
        "Remote Desktop Services" `
        "Disable TermService service" `
        "RDP services allow interactive remote login and should be disabled for zero-trust endpoints."
}

# =====================================================
# 3. Remote Assistance (Registry enforced)
# =====================================================
try {
    $ra = Get-ItemProperty `
        'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' `
        -Name fAllowToGetHelp

    if ($ra.fAllowToGetHelp -eq 0) {
        Add-Result "Remote Assistance" "PASS" "Registry enforced (fAllowToGetHelp=0)"
    } else {
        Add-Result "Remote Assistance" "FAIL" "Registry value=$($ra.fAllowToGetHelp)"
        Add-Recommendation `
            "Remote Assistance" `
            "Set fAllowToGetHelp=0 in registry" `
            "Disables consent-based support access and prevents UI re-enablement."
    }
}
catch {
    Add-Result "Remote Assistance" "FAIL" "Registry key missing"
    Add-Recommendation `
        "Remote Assistance" `
        "Create and enforce registry key" `
        "Ensures Remote Assistance cannot be enabled accidentally or via UI."
}

# =====================================================
# 4. SSH Server
# =====================================================
$sshd = Get-Service sshd -ErrorAction SilentlyContinue

if (-not $sshd) {
    Add-Result "SSH Server" "PASS" "Not installed"
} elseif ($sshd.Status -eq 'Stopped' -and $sshd.StartType -eq 'Disabled') {
    Add-Result "SSH Server" "PASS" "Installed but disabled"
} else {
    Add-Result "SSH Server" "FAIL" "$($sshd.Status), $($sshd.StartType)"
    Add-Recommendation `
        "SSH Server" `
        "Disable or remove OpenSSH.Server" `
        "SSH provides a remote shell and should not be present on a locked-down workstation."
}

# =====================================================
# 5. Firewall Profiles
# =====================================================
$profiles = Get-NetFirewallProfile
$fwOk = $true

foreach ($p in $profiles) {
    if (-not ($p.Enabled -and $p.DefaultInboundAction -eq 'Block')) {
        $fwOk = $false
    }
}

if ($fwOk) {
    Add-Result "Windows Firewall" "PASS" "Inbound blocked on all profiles"
} else {
    Add-Result "Windows Firewall" "FAIL" "One or more profiles allow inbound traffic"
    Add-Recommendation `
        "Windows Firewall" `
        "Enable firewall and block inbound traffic on all profiles" `
        "Firewall is the final enforcement layer preventing accidental exposure."
}

# =====================================================
# WRITE REPORT
# =====================================================
"Remote Access Lockdown Verification Report" | Out-File $ReportPath
"Generated: $TimeStamp" | Out-File $ReportPath -Append
"" | Out-File $ReportPath -Append

"=== Security Control Results ===" | Out-File $ReportPath -Append
foreach ($r in $Results) {
    "$($r.Control): $($r.Status)" | Out-File $ReportPath -Append
    "  Details: $($r.Details)" | Out-File $ReportPath -Append
}

"" | Out-File $ReportPath -Append
"=== Recommendations ===" | Out-File $ReportPath -Append

if ($Recommendations.Count -eq 0) {
    "No corrective actions required. All controls meet recommended posture." |
        Out-File $ReportPath -Append
}
else {
    foreach ($rec in $Recommendations) {
        "$($rec.Control)" | Out-File $ReportPath -Append
        "  Recommendation: $($rec.Recommendation)" | Out-File $ReportPath -Append
        "  Rationale     : $($rec.Rationale)" | Out-File $ReportPath -Append
        "" | Out-File $ReportPath -Append
    }
}

Write-Host ""
Write-Host "Verification complete."
Write-Host "Report saved to:"
Write-Host $ReportPath
