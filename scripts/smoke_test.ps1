param(
  [string]$ApiBase = 'http://localhost:8000/api',
  [string]$AnalystPassword = 'CyberGuard2026!',
  [switch]$IncludeUnitTests
)

# End-to-end smoke test for a running PhishSenital stack.
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\smoke_test.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\smoke_test.ps1 -IncludeUnitTests

$ErrorActionPreference = 'Stop'
$passed = 0
$failed = 0

function Check {
  param([string]$Name, [scriptblock]$Body)
  try {
    $detail = & $Body
    $script:passed++
    Write-Host "[PASS] $Name :: $detail"
  } catch {
    $script:failed++
    Write-Host "[FAIL] $Name :: $($_.Exception.Message)"
    if ($_.ErrorDetails) { Write-Host "       $($_.ErrorDetails.Message)" }
  }
}

function Get-Json([string]$Path) {
  Invoke-RestMethod -Uri "$ApiBase$Path" -TimeoutSec 30
}

function Post-Json([string]$Path, $Body) {
  $json = $Body | ConvertTo-Json -Compress -Depth 10
  Invoke-RestMethod -Uri "$ApiBase$Path" -Method Post -ContentType 'application/json' -Body $json -TimeoutSec 60
}

Write-Host "PhishSenital smoke test -> $ApiBase"
Write-Host ('-' * 70)

Check 'Backend health' {
  $r = Get-Json '/health'
  if ($r.status -ne 'HEALTHY') { throw "status=$($r.status)" }
  "status=$($r.status), groq_configured=$($r.groq_configured)"
}

Check 'Dashboard statistics' {
  $r = Get-Json '/dashboard/stats'
  "scans=$($r.total_scans), threats=$($r.threats_detected), quarantined=$($r.files_quarantined)"
}

Check 'Agent catalogue' {
  $r = Get-Json '/agents'
  $count = @($r).Count
  if ($count -ne 5) { throw "expected 5 agents, got $count" }
  "agents=$count"
}

$script:emailScan = $null
Check 'Email scan (JSON manual mode)' {
  $script:emailScan = Post-Json '/scan/email' @{
    sender  = 'security@secure-chase-update.com'
    subject = 'Immediate action required: Unauthorized access detected'
    body    = 'Your account has been suspended. Please enter your password within 24 hours.'
  }
  if ($script:emailScan.risk_score -lt 20) { throw "score=$($script:emailScan.risk_score)" }
  "score=$($script:emailScan.risk_score), level=$($script:emailScan.risk_level), indicators=$(@($script:emailScan.indicators).Count)"
}

Check 'Website scan (JSON mode)' {
  $r = Post-Json '/scan/website' @{ url = 'https://paypa1-security-login.xyz/account' }
  if ($r.risk_score -lt 20) { throw "score=$($r.risk_score)" }
  "score=$($r.risk_score), level=$($r.risk_level), indicators=$(@($r.indicators).Count)"
}

Check 'QR scan (JSON manual payload)' {
  $r = Post-Json '/scan/qr' @{
    manual_content = 'upi://pay?pa=scammer@okhdfc&pn=QuickRefund&tn=Power%20bill%20overdue%20fine&am=2500'
  }
  if ($r.risk_score -lt 20) { throw "score=$($r.risk_score)" }
  "score=$($r.risk_score), level=$($r.risk_level), indicators=$(@($r.indicators).Count)"
}

Check 'QR scan (image upload / multipart)' {
  $tmpPng = Join-Path $env:TEMP 'cyberguard_smoke_qr.png'
  $code = @"
import qrcode
qr = qrcode.QRCode(box_size=6, border=2)
qr.add_data('MEETING-MEMO-SMOKE-TEST')
qr.make(fit=True)
qr.make_image(fill_color='black', back_color='white').save(r'$tmpPng')
"@
  py -c $code | Out-Null
  if (-not (Test-Path $tmpPng)) { throw 'QR fixture could not be generated' }
  $raw = curl.exe -s -X POST -F "file=@$tmpPng;type=image/png" "$ApiBase/scan/qr"
  Remove-Item $tmpPng -Force -ErrorAction SilentlyContinue
  $r = $raw | ConvertFrom-Json
  if (-not $r.id) { throw "unexpected response: $raw" }
  "id=$($r.id), score=$($r.risk_score)"
}

Check 'Incident list' {
  $r = Get-Json '/incidents'
  "total=$($r.total)"
}

Check 'Quarantine integrity verification' {
  $items = Get-Json '/quarantine'
  $items = @($items)
  $bad = @()
  foreach ($item in $items) {
    $v = Get-Json "/quarantine/$($item.id)/verify"
    if ($v.status -ne 'INTEGRITY_VERIFIED' -and $v.status -ne 'FILE_MISSING') {
      $bad += "$($item.original_filename)=$($v.status)"
    }
  }
  if ($bad.Count -gt 0) { throw ($bad -join ', ') }
  "verified=$($items.Count) records"
}

Check 'Reports summary' {
  $r = Get-Json '/reports'
  "total_scans=$($r.summary.total_scans), incidents=$($r.summary.total_incidents)"
}

Check 'CSV export' {
  $r = Invoke-WebRequest -Uri "$ApiBase/reports/export/csv" -TimeoutSec 30 -UseBasicParsing
  if ($r.StatusCode -ne 200) { throw "HTTP $($r.StatusCode)" }
  "bytes=$($r.RawContentLength)"
}

Check 'PDF report generation' {
  if (-not $script:emailScan) { throw 'no email scan available' }
  $tmpPdf = Join-Path $env:TEMP 'cyberguard_smoke_report.pdf'
  Invoke-WebRequest -Uri "$ApiBase/reports/$($script:emailScan.id)/pdf" -OutFile $tmpPdf -TimeoutSec 30
  $sig = [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($tmpPdf)[0..3])
  Remove-Item $tmpPdf -Force -ErrorAction SilentlyContinue
  if ($sig -ne '%PDF') { throw "signature=$sig" }
  "signature=$sig"
}

Check 'Settings endpoint' {
  $r = Get-Json '/settings'
  "model=$($r.groq_model), groq_key_configured=$($r.groq_api_key_configured)"
}

Check 'Threat intelligence' {
  $r = Get-Json '/threat-intel'
  "active_blocklist=$($r.active_blocklist_count)"
}

Check 'Demo auth /me' {
  $r = Get-Json '/auth/me'
  "user=$($r.username), role=$($r.role)"
}

Check 'Login and bearer token' {
  $r = Post-Json '/auth/login' @{ username = 'analyst'; password = $AnalystPassword }
  if (-not $r.access_token) { throw 'no access_token returned' }
  "token_type=$($r.token_type), user=$($r.user.username)"
}

if ($IncludeUnitTests) {
  Check 'Unit + API + hardening suites (27 tests)' {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $backup = Join-Path $env:TEMP 'cyberguard_smoke_db_backup.db'
    Push-Location $repoRoot
    $previousEap = $ErrorActionPreference
    try {
      $ErrorActionPreference = 'Continue'  # Python deprecation warnings go to stderr
      Copy-Item 'backend\cybersecurity_platform.db' $backup -Force
      $output = & py -m unittest backend/tests/test_detection.py backend/tests/test_api_scans.py backend/tests/test_hardening.py 2>&1
      $code = $LASTEXITCODE
      Copy-Item $backup 'backend\cybersecurity_platform.db' -Force
    } finally {
      $ErrorActionPreference = $previousEap
      Pop-Location
    }
    if ($code -ne 0) { throw ($output -join "`n") }
    '27/27 passed'
  }
}

Write-Host ('-' * 70)
Write-Host "RESULT: passed=$passed failed=$failed"
if ($failed -gt 0) { exit 1 }
