# Usage

## Syntax validation

```powershell
$files = Get-ChildItem .\src -Filter *.ps1
foreach ($file in $files) {
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
        $file.FullName,
        [ref]$tokens,
        [ref]$errors
    ) | Out-Null
    [PSCustomObject]@{ Script = $file.Name; ParseErrors = @($errors).Count }
}
```

## Controlled execution pattern

```powershell
Set-Location .\src
.\WindowsSecurityReview.ps1
```

Run only one script at a time, read the output, and retain reports outside the Git repository.
