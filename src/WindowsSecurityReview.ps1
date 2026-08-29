Write-Host "=============================="
Write-Host " Windows Security Review"
Write-Host "==============================`n"

$results = @()

# 1. Defender status
$defender = Get-MpComputerStatus

$results += [PSCustomObject]@{
    Check = "Defender Running Mode"
    Value = $defender.AMRunningMode
    Status = if ($defender.AMRunningMode -eq "Passive Mode") { "PASS" } else { "WARN" }
}

$results += [PSCustomObject]@{
    Check = "Defender Real-Time Protection"
    Value = $defender.RealTimeProtectionEnabled
    Status = if ($defender.RealTimeProtectionEnabled -eq $false) { "PASS" } else { "FAIL" }
}

# 2. Windows Security Center Antivirus Registration
$avProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct

foreach ($av in $avProducts) {
    $results += [PSCustomObject]@{
        Check = "AV Registered"
        Value = "$($av.displayName) (State: $($av.productState))"
        Status = "INFO"
    }
}

# 3. McAfee service health
$mcafeeServices = Get-Service | Where-Object {
    $_.Name -match "mcafee|mfe|mfemms|masvc"
}

if ($mcafeeServices) {
    $running = $mcafeeServices | Where-Object { $_.Status -eq "Running" }
    $results += [PSCustomObject]@{
        Check = "McAfee Services Running"
        Value = "$($running.Count)/$($mcafeeServices.Count)"
        Status = if ($running.Count -gt 0) { "PASS" } else { "FAIL" }
    }
} else {
    $results += [PSCustomObject]@{
        Check = "McAfee Services"
        Value = "Not found"
        Status = "FAIL"
    }
}

# 4. Final verdict
$finalStatus =
    if ($results.Status -contains "FAIL") { "FAIL" }
    elseif ($results.Status -contains "WARN") { "WARN" }
    else { "PASS" }

# Output
$results | Format-Table -AutoSize

Write-Host "`n=============================="
Write-Host " FINAL VERDICT: $finalStatus"
Write-Host "=============================="

if ($finalStatus -eq "PASS") {
    Write-Host "✅ System correctly configured: McAfee active, Defender passive." -ForegroundColor Green
}
elseif ($finalStatus -eq "WARN") {
    Write-Host "⚠ Review recommended: minor deviations detected." -ForegroundColor Yellow
}
else {
    Write-Host "❌ Security misconfiguration detected." -ForegroundColor Red
}
