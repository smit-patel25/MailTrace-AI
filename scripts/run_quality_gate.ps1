$ErrorActionPreference = "Stop"

Write-Host "Starting MailTrace AI Automated Quality Gate..." -ForegroundColor Cyan

# 1. Activate Environment
if (Test-Path ".venv\Scripts\Activate.ps1") {
    Write-Host "Activating virtual environment..."
    . ".venv\Scripts\Activate.ps1"
} else {
    Write-Host "Warning: .venv\Scripts\Activate.ps1 not found. Using current environment." -ForegroundColor Yellow
}

$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ssZ"
$ReportContent = "# MailTrace AI Quality Gate Report`n`n**Run Date:** $Timestamp`n`n"

$Failed = $false

# 2 & 3. Run Pytest Suite (includes AppTest workflows)
Write-Host "`nRunning test matrix (Unit & System tests)..." -ForegroundColor Cyan
$PytestOutput = & pytest
$PytestExitCode = $LASTEXITCODE

if ($PytestExitCode -ne 0) {
    Write-Host "Pytest suite failed." -ForegroundColor Red
    $ReportContent += "## Pytest Status: ❌ FAILED`n`n"
    $Failed = $true
} else {
    Write-Host "Pytest suite passed." -ForegroundColor Green
    $ReportContent += "## Pytest Status: ✅ PASSED`n`n"
}

# Add pytest output to report safely
$ReportContent += "```text`n" + ($PytestOutput -join "`n") + "`n````n`n"

# 4. Secret / Excluded File Check
Write-Host "`nRunning Security and Repository Checks..." -ForegroundColor Cyan
$SecurityFailed = $false

# Check for secrets (Google API Keys usually start with AIza)
# We only grep in tracked files, excluding the scripts/ folder or tests
$GitGrepOutput = git grep -iE "AIza[A-Za-z0-9_-]{35}" -- ":!scripts/*" ":!tests/*" 2>$null
if ($GitGrepOutput) {
    Write-Host "SECURITY ALERT: Potential API key found in tracked files!" -ForegroundColor Red
    $ReportContent += "## Security Status: ❌ FAILED (API Key matched)`n"
    $SecurityFailed = $true
}

# Check if sensitive files are tracked
$TrackedFiles = git ls-files
$SensitiveFiles = @(".env", "database.sqlite3", "data/mailtrace.db")

foreach ($file in $SensitiveFiles) {
    if ($TrackedFiles -contains $file) {
        Write-Host "SECURITY ALERT: $file is tracked by Git!" -ForegroundColor Red
        $ReportContent += "## Security Status: ❌ FAILED ($file is tracked)`n"
        $SecurityFailed = $true
    }
}

if (-not $SecurityFailed) {
    Write-Host "Security and repository checks passed." -ForegroundColor Green
    $ReportContent += "## Security Status: ✅ PASSED`n`n"
} else {
    $Failed = $true
}

# 5. Write Report
$ReportContent += "## Summary`n"
if ($Failed) {
    $ReportContent += "Quality gate failed. Please review the errors above."
    Set-Content -Path "QUALITY_REPORT.md" -Value $ReportContent
    Write-Host "`nQuality gate failed. Report written to QUALITY_REPORT.md" -ForegroundColor Red
    exit 1
} else {
    $ReportContent += "All quality gate checks passed successfully."
    Set-Content -Path "QUALITY_REPORT.md" -Value $ReportContent
    Write-Host "`nAll checks passed. Report written to QUALITY_REPORT.md" -ForegroundColor Green
    exit 0
}
