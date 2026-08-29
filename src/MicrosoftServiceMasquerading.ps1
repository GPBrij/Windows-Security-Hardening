# ===============================
# Windows Defensive Security Audit
# ===============================

$TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$BasePath = "$env:PUBLIC\SecurityAudit_$TimeStamp"
New-Item -ItemType Directory -Path $BasePath | Out-Null

$ReportFile = "$BasePath\SecurityAudit_Report.txt"

Function Write-Report {
    param ($Text)
    $Text | Out-File -Append -FilePath $ReportFile
}

Write-Report "========================================="
Write-Report "WINDOWS DEFENSIVE SECURITY AUDIT"
Write-Report "Generated: $(Get-Date)"
Write-Report "========================================="
Write-Report ""

# ----------------------------------------
# 1. Microsoft Service Masquerading Check
# ----------------------------------------

$ServiceFindings = @()

Get-WmiObject Win32_Service | ForEach-Object {
    if ($_.DisplayName -match "Microsoft|Windows") {

        $BinaryPath = $_.PathName
        $Suspicious = $false

        if ($BinaryPath -notmatch "System32|SysWOW64|Windows") {
            $Suspicious = $true
        }

        if ($_.Name -match "[^a-zA-Z0-9\-]") {
            $Suspicious = $true
        }

        if ($Suspicious) {
            $ServiceFindings += [PSCustomObject]@{
                Name = $_.Name
                DisplayName = $_.DisplayName
                Path = $BinaryPath
                StartMode = $_.StartMode
                State = $_.State
            }
        }
    }
}

$ServiceFindings | Export-Csv "$BasePath\Services_Findings.csv" -NoTypeInformation

Write-Report "[+] Service Masquerading Scan Completed"
Write-Report "    Findings: $($ServiceFindings.Count)"
Write-Report ""

# ----------------------------------------
# 2. Registry Naming & Persistence Scan
# ----------------------------------------

$RegistryPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

$RegistryFindings = @()

foreach ($Path in $RegistryPaths) {
    if (Test-Path $Path) {
        Get-ItemProperty $Path | Get-Member -MemberType NoteProperty | ForEach-Object {

            if ($_.Name -match "\s{2,}|[^\x00-\x7F]") {
                $RegistryFindings += [PSCustomObject]@{
                    RegistryPath = $Path
                    ValueName = $_.Name
                    Issue = "Suspicious naming (whitespace/unicode)"
                }
            }
        }
    }
}

$RegistryFindings | Export-Csv "$BasePath\Registry_Findings.csv" -NoTypeInformation

Write-Report "[+] Registry Persistence Scan Completed"
Write-Report "    Findings: $($RegistryFindings.Count)"
Write-Report ""

# ----------------------------------------
# 3. Scheduled Task Inspection
# ----------------------------------------

$TaskFindings = Get-ScheduledTask | Where-Object {
    $_.TaskPath -notmatch "Microsoft"
} | Select TaskName, TaskPath, State

$TaskFindings | Export-Csv "$BasePath\Tasks_Findings.csv" -NoTypeInformation

Write-Report "[+] Scheduled Task Scan Completed"
Write-Report "    Findings: $($TaskFindings.Count)"
Write-Report ""

# ----------------------------------------
# 4. Unsigned Driver Check
# ----------------------------------------

$UnsignedDrivers = Get-CimInstance Win32_PnPSignedDriver |
Where-Object { $_.IsSigned -eq $false } |
Select DeviceName, DriverVersion, Manufacturer

$UnsignedDrivers | Out-File "$BasePath\Unsigned_Drivers.txt"

Write-Report "[+] Driver Signature Scan Completed"
Write-Report "    Unsigned drivers detected: $($UnsignedDrivers.Count)"
Write-Report ""

# ----------------------------------------
# Completion
# ----------------------------------------

Write-Report "========================================="
Write-Report "AUDIT COMPLETED"
Write-Report "Review CSV files for detailed findings."
Write-Report "========================================="
