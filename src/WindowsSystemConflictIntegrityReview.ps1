Write-Host "========================================"
Write-Host " Windows System Conflict & Integrity Review"
Write-Host "========================================`n"

$results = @()

# ------------------------------------
# 1. Security Product Conflict Review
# ------------------------------------
$avProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct

$activeAVs = @()

foreach ($av in $avProducts) {
    if ($av.productState -band 0x10000) {
        $activeAVs += $av.displayName
    }
}

$results += [PSCustomObject]@{
    Check  = "Active Antivirus Count"
    Value  = $activeAVs.Count
    Status = if ($activeAVs.Count -eq 1) { "PASS" } else { "FAIL" }
}

# ------------------------------------
# 2. Broken Service Binary Paths
# ------------------------------------
$brokenServices = Get-CimInstance Win32_Service | Where-Object {
    $_.PathName -and
    -not (Test-Path ($_.PathName -replace '"','').Split(" ")[0])
}

$results += [PSCustomObject]@{
    Check  = "Broken Service Binaries"
    Value  = $brokenServices.Count
    Status = if ($brokenServices.Count -eq 0) { "PASS" } else { "WARN" }
}

# ------------------------------------
# 3. Failed / Stopped Critical Services
# ------------------------------------
$failedServices = Get-Service | Where-Object {
    $_.Status -ne "Running" -and $_.StartType -eq "Automatic"
}

$results += [PSCustomObject]@{
    Check  = "Auto Services Not Running"
    Value  = $failedServices.Count
    Status = if ($failedServices.Count -eq 0) { "PASS" } else { "WARN" }
}

# ------------------------------------
# 4. Startup Link & Executable Validation
# ------------------------------------
$startupPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
)

$brokenStartup = @()

foreach ($path in $startupPaths) {
    if (Test-Path $path) {
        Get-ItemProperty $path | ForEach-Object {
            $_.PSObject.Properties | Where-Object {
                $_.Name -notmatch "^PS"
            } | ForEach-Object {
                $exe = $_.Value -replace '"',''
                if (-not (Test-Path $exe.Split(" ")[0])) {
                    $brokenStartup += $_.Name
                }
            }
        }
    }
}

$results += [PSCustomObject]@{
    Check  = "Broken Startup Links"
    Value  = $brokenStartup.Count
    Status = if ($brokenStartup.Count -eq 0) { "PASS" } else { "WARN" }
}

# ------------------------------------
# 5. Recent Application Crash Indicators
# ------------------------------------
$appErrors = Get-WinEvent -FilterHashtable @{
    LogName = "Application"
    Level   = 2
} -MaxEvents 50 -ErrorAction SilentlyContinue

$results += [PSCustomObject]@{
    Check  = "Recent Application Errors"
    Value  = $appErrors.Count
    Status = if ($appErrors.Count -lt 5) { "PASS" } else { "WARN" }
}

# ------------------------------------
# 6. Firewall Ownership Conflict Check
# ------------------------------------
$firewallProfiles = Get-NetFirewallProfile

$enabledFirewalls = ($firewallProfiles | Where-Object { $_.Enabled }).Count

$results += [PSCustomObject]@{
    Check  = "Enabled Firewall Profiles"
    Value  = $enabledFirewalls
    Status = if ($enabledFirewalls -ge 1) { "PASS" } else { "FAIL" }
}

# ------------------------------------
# Final Verdict
# ------------------------------------
$final =
    if ($results.Status -contains "FAIL") { "FAIL" }
    elseif ($results.Status -contains "WARN") { "WARN" }
    else { "PASS" }

$results | Format-Table -AutoSize

Write-Host "`n========================================"
Write-Host " FINAL SYSTEM HEALTH: $final"
Write-Host "========================================"

switch ($final) {
    "PASS" { Write-Host "✅ No application conflicts or link breakages detected." -ForegroundColor Green }
    "WARN" { Write-Host "⚠ Minor issues detected — review recommended." -ForegroundColor Yellow }
    "FAIL" { Write-Host "❌ Critical conflicts or breakages detected." -ForegroundColor Red }
}
