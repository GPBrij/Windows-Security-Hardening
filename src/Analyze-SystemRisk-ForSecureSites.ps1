# =============================================================
# System Risk Profile Analysis – Banking Perimeter Compatibility
# Passive, local inspection only
# =============================================================

$Output = "System_Risk_Profile_Report_$((Get-Date).ToString('yyyyMMdd_HHmmss')).txt"
$Now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

function Write-Report {
    param ($Text)
    $Text | Tee-Object -FilePath $Output -Append
}

Write-Report "============================================================"
Write-Report "SYSTEM RISK PROFILE ANALYSIS (BANK PERIMETER VIEW)"
Write-Report "Generated: $Now"
Write-Report "============================================================"
Write-Report ""

# -------------------------------------------------------------
# 1. OS & Crypto Stack
# -------------------------------------------------------------
Write-Report "[1] OPERATING SYSTEM & CRYPTO STACK"
$os = Get-CimInstance Win32_OperatingSystem
Write-Report " - OS            : $($os.Caption)"
Write-Report " - Version       : $($os.Version)"
Write-Report " - Build         : $($os.BuildNumber)"
Write-Report " - Architecture  : $($os.OSArchitecture)"
Write-Report " - TLS Provider  : Windows Schannel (.NET / PowerShell)"
Write-Report ""

# -------------------------------------------------------------
# 2. Enabled TLS Versions
# -------------------------------------------------------------
Write-Report "[2] ENABLED TLS VERSIONS (SYSTEM POLICY)"
$tlsKeys = @(
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client",
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client"
)

foreach ($k in $tlsKeys) {
    if (Test-Path $k) {
        $v = Get-ItemProperty $k
        Write-Report " - $k"
        $v.PSObject.Properties | ForEach-Object {
            Write-Report "   $($_.Name): $($_.Value)"
        }
    }
    else {
        Write-Report " - $k : Not explicitly configured"
    }
}
Write-Report ""

# -------------------------------------------------------------
# 3. Cipher Suite Policy
# -------------------------------------------------------------
Write-Report "[3] TLS CIPHER SUITE POLICY"
try {
    $ciphers = Get-TlsCipherSuite
    Write-Report " - Cipher suites enabled: $($ciphers.Count)"
    Write-Report " - Top 5 cipher preference:"
    $ciphers | Select-Object -First 5 | ForEach-Object {
        Write-Report "   $($_.Name)"
    }
}
catch {
    Write-Report " - Cipher suite enumeration not permitted"
}
Write-Report ""

# -------------------------------------------------------------
# 4. Endpoint Hardening Signals
# -------------------------------------------------------------
Write-Report "[4] ENDPOINT HARDENING / SECURITY FEATURES"

$features = @{
    "Credential Guard" = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
    "AMSI"             = "HKLM:\SOFTWARE\Microsoft\AMSI"
    "Defender"         = "HKLM:\SOFTWARE\Microsoft\Windows Defender"
}

foreach ($f in $features.Keys) {
    if (Test-Path $features[$f]) {
        Write-Report " - $f detected"
    }
    else {
        Write-Report " - $f not detected"
    }
}
Write-Report ""

# -------------------------------------------------------------
# 5. Proxy & Inspection Indicators
# -------------------------------------------------------------
Write-Report "[5] PROXY / TLS INSPECTION INDICATORS"

try {
    $proxy = [System.Net.WebRequest]::GetSystemWebProxy()
    Write-Report " - System proxy object present"
}
catch {
    Write-Report " - No explicit system proxy"
}

Write-Report ""

# -------------------------------------------------------------
# 6. Risk Interpretation (Bank View)
# -------------------------------------------------------------
Write-Report "============================================================"
Write-Report "BANK PERIMETER RISK INTERPRETATION"
Write-Report "============================================================"
Write-Report "From a banking WAF / bot-management perspective:"
Write-Report ""
Write-Report " - Non-browser TLS stack detected (PowerShell / Schannel)"
Write-Report " - Hardened enterprise OS profile"
Write-Report " - TLS cipher order differs from consumer browsers"
Write-Report " - Headless / automated client appearance"
Write-Report ""
Write-Report "These characteristics often trigger:"
Write-Report " - TLS fingerprint rejection"
Write-Report " - Silent connection reset"
Write-Report " - Pre-authentication blocking"
Write-Report ""
Write-Report "Result: Client classified as higher-risk despite legitimacy."
Write-Report "============================================================"

Write-Host ""
Write-Host "✅ System risk profile report generated:"
Write-Host "➡ $Output"

