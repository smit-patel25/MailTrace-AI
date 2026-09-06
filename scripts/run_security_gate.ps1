$ErrorActionPreference = "Stop"

Write-Host "Starting MailTrace AI Professional Security Gate Phase 1..." -ForegroundColor Cyan

# 1. Activate Environment
if (Test-Path ".venv\Scripts\python.exe") {
    $PythonExe = ".\.venv\Scripts\python.exe"
    Write-Host "Using Python environment at $PythonExe"
} else {
    Write-Host "FATAL ERROR: .venv\Scripts\python.exe not found. Please install the virtual environment first." -ForegroundColor Red
    exit 1
}

$Failed = $false
$Summary = @()

# 2. Pytest Suite
Write-Host "`n[1/6] Running full pytest suite..." -ForegroundColor Cyan
& $PythonExe -m pytest -q
if ($LASTEXITCODE -ne 0) {
    Write-Host "Pytest suite failed." -ForegroundColor Red
    $Summary += "Pytest Status: [FAIL]"
    $Failed = $true
} else {
    Write-Host "Pytest suite passed." -ForegroundColor Green
    $Summary += "Pytest Status: [PASS]"
}

# 3. Ruff
Write-Host "`n[2/6] Running Ruff static checks..." -ForegroundColor Cyan
& $PythonExe -m ruff check .
if ($LASTEXITCODE -ne 0) {
    Write-Host "Ruff checks failed." -ForegroundColor Red
    $Summary += "Ruff Status: [FAIL]"
    $Failed = $true
} else {
    Write-Host "Ruff checks passed." -ForegroundColor Green
    $Summary += "Ruff Status: [PASS]"
}

# 4. Bandit
Write-Host "`n[3/6] Running Bandit security analysis..." -ForegroundColor Cyan
& $PythonExe -m bandit -r app.py modules pages -ll -ii
if ($LASTEXITCODE -ne 0) {
    Write-Host "Bandit analysis failed." -ForegroundColor Red
    $Summary += "Bandit Status: [FAIL]"
    $Failed = $true
} else {
    Write-Host "Bandit analysis passed." -ForegroundColor Green
    $Summary += "Bandit Status: [PASS]"
}

# 5. pip-audit
Write-Host "`n[4/6] Running pip-audit..." -ForegroundColor Cyan
& $PythonExe -m pip_audit -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    Write-Host "pip-audit failed." -ForegroundColor Red
    $Summary += "pip-audit Status: [FAIL]"
    $Failed = $true
} else {
    Write-Host "pip-audit passed." -ForegroundColor Green
    $Summary += "pip-audit Status: [PASS]"
}

# 6. pip check
Write-Host "`n[5/6] Running pip check..." -ForegroundColor Cyan
& $PythonExe -m pip check
if ($LASTEXITCODE -ne 0) {
    Write-Host "pip check failed." -ForegroundColor Red
    $Summary += "pip check Status: [FAIL]"
    $Failed = $true
} else {
    Write-Host "pip check passed." -ForegroundColor Green
    $Summary += "pip check Status: [PASS]"
}

# 7. Repository/Secret Safety Checks
Write-Host "`n[6/6] Running Repository and Secret Safety Checks..." -ForegroundColor Cyan
$SecurityFailed = $false

$GitGrepOutput = git grep -iE "AIza[A-Za-z0-9_-]{35}" -- ":!scripts/*" ":!tests/*" 2>$null
if ($GitGrepOutput) {
    Write-Host "SECURITY ALERT: Potential API key found in tracked files!" -ForegroundColor Red
    $Summary += "Secrets Status: [FAIL] (API Key matched)"
    $SecurityFailed = $true
}

$TrackedFiles = git ls-files
$SensitiveFiles = @(".env", "database.sqlite3", "data/mailtrace.db")

foreach ($file in $SensitiveFiles) {
    if ($TrackedFiles -contains $file) {
        Write-Host "SECURITY ALERT: $file is tracked by Git!" -ForegroundColor Red
        $Summary += "Repository Status: [FAIL] ($file is tracked)"
        $SecurityFailed = $true
    }
}

if (-not $SecurityFailed) {
    Write-Host "Security and repository checks passed." -ForegroundColor Green
    $Summary += "Secret/Repo Checks: [PASS]"
} else {
    $Failed = $true
}

# 8. Report Summary
Write-Host "`n--- Security Gate Summary ---" -ForegroundColor Cyan
foreach ($line in $Summary) {
    if ($line -match "\[FAIL\]") {
        Write-Host $line -ForegroundColor Red
    } else {
        Write-Host $line -ForegroundColor Green
    }
}

if ($Failed) {
    Write-Host "`nSecurity Gate FAILED. Please review the output above." -ForegroundColor Red
    exit 1
} else {
    Write-Host "`nAll Security Gate checks PASSED successfully." -ForegroundColor Green
    exit 0
}
