# Gọi /api/auth/login hai lần: thiết bị 1 phải 200; thiết bị 2 phải 403 khi MAX_DEVICES_PER_USER=1 (mặc định server).
# Chạy từ thư mục server hoặc bất kỳ đâu (script tự tìm server\.env).
#
# Giá trị (ưu tiên từ trên xuống):
#   1) Biến môi trường process: EF_TEST_BASE, EF_TEST_APP_SECRET, EF_TEST_EMAIL, EF_TEST_PASSWORD
#   2) File server\.env: APP_SECRET (dùng làm X-App-Secret nếu chưa set EF_TEST_APP_SECRET)
#      + EF_TEST_EMAIL / EF_TEST_PASSWORD HOẶC TEST_LOGIN_EMAIL / TEST_LOGIN_PASSWORD
#   3) EF_TEST_BASE mặc định: https://server-nine-xi-24.vercel.app (đổi trong .env nếu project khác)
#
# KHÔNG cần SUPABASE_SERVICE_ROLE_KEY cho script này.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\test-licensed-login-devices.ps1

$ErrorActionPreference = "Stop"

function Read-DotEnvFile {
  param([string]$Path)
  $map = @{}
  if (-not (Test-Path -LiteralPath $Path)) { return $map }
  Get-Content -LiteralPath $Path | ForEach-Object {
    $line = $_.Trim()
    if ($line -match '^\s*#' -or $line -eq "") { return }
    $eq = $line.IndexOf("=")
    if ($eq -lt 1) { return }
    $k = $line.Substring(0, $eq).Trim()
    $v = $line.Substring($eq + 1).Trim()
    if ($v.Length -ge 2 -and $v.StartsWith('"') -and $v.EndsWith('"')) {
      $v = $v.Substring(1, $v.Length - 2)
    }
    if ($k) { $map[$k] = $v }
  }
  return $map
}

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$serverRoot = Split-Path -Parent $scriptDir
$dotenv = Read-DotEnvFile (Join-Path $serverRoot ".env")

function Pick([string]$ProcessKey, [string]$DotKey1, [string]$DotKey2) {
  $p = [Environment]::GetEnvironmentVariable($ProcessKey, "Process")
  if ($p) { return $p.Trim() }
  if ($DotKey1 -and $dotenv[$DotKey1]) { return [string]$dotenv[$DotKey1].Trim() }
  if ($DotKey2 -and $dotenv[$DotKey2]) { return [string]$dotenv[$DotKey2].Trim() }
  return ""
}

$baseRaw = Pick "EF_TEST_BASE" "EF_TEST_BASE" ""
$base = if ($baseRaw) { $baseRaw.TrimEnd("/") } else { "https://server-nine-xi-24.vercel.app" }

$sec = Pick "EF_TEST_APP_SECRET" "EF_TEST_APP_SECRET" ""
if (-not $sec -and $dotenv["APP_SECRET"]) {
  $sec = [string]$dotenv["APP_SECRET"].Trim()
}

$email = Pick "EF_TEST_EMAIL" "EF_TEST_EMAIL" "TEST_LOGIN_EMAIL"
$pass = Pick "EF_TEST_PASSWORD" "EF_TEST_PASSWORD" "TEST_LOGIN_PASSWORD"

if (-not $sec) {
  Write-Error "Missing APP_SECRET in server/.env or EF_TEST_APP_SECRET (do not use service_role)."
  exit 1
}
if (-not $email -or -not $pass) {
  Write-Error "Missing test credentials. Add to server/.env: EF_TEST_EMAIL / EF_TEST_PASSWORD (or TEST_LOGIN_EMAIL / TEST_LOGIN_PASSWORD)."
  exit 1
}

function Invoke-LoginTry([string]$deviceId) {
  $uri = "$base/api/auth/login"
  $body = @{ email = $email; password = $pass } | ConvertTo-Json
  try {
    $r = Invoke-WebRequest -Uri $uri -Method POST -ContentType "application/json" `
      -Headers @{ "X-App-Secret" = $sec; "X-Device-ID" = $deviceId } `
      -Body $body -UseBasicParsing
    return @{ Status = [int]$r.StatusCode; Json = ($r.Content | ConvertFrom-Json); Body = $r.Content }
  } catch {
    $code = 0
    $txt = ""
    $resp = $_.Exception.Response
    if ($null -ne $resp) {
      $code = [int]$resp.StatusCode
      $stream = $resp.GetResponseStream()
      if ($null -ne $stream) {
        $sr = New-Object System.IO.StreamReader($stream)
        $txt = $sr.ReadToEnd()
        $sr.Close()
      }
    }
    $j = $null
    if ($txt) { try { $j = $txt | ConvertFrom-Json } catch {} }
    return @{ Status = $code; Json = $j; Body = $txt }
  }
}

Write-Host ">> Base: $base"
Write-Host ">> Device A (login)..."
$ra = Invoke-LoginTry "test-device-aaaaaaaa"
if ($ra.Status -ne 200) {
  Write-Error "Device A expected HTTP 200, got $($ra.Status) $($ra.Body)"
  exit 1
}
Write-Host "   HTTP $($ra.Status) access_token len:" ($ra.Json.access_token.Length)

Write-Host ">> Device B (second fingerprint, should fail if MAX_DEVICES_PER_USER=1)..."
$rb = Invoke-LoginTry "test-device-bbbbbbbb"
if ($rb.Status -eq 403) {
  Write-Host "   HTTP 403 OK: device_limit_reached (one device per user)."
} elseif ($rb.Status -eq 200) {
  Write-Host "   HTTP 200: server still allows a second device. Set Vercel MAX_DEVICES_PER_USER=1 and redeploy, then admin Reset thiet bi."
  Write-Host "   access_token len:" ($rb.Json.access_token.Length)
} else {
  Write-Error "Device B unexpected HTTP $($rb.Status) $($rb.Body)"
  exit 1
}

Write-Host "OK - check admin Xem thiet bi (expect 1 row when limit is 1 after reset)."
