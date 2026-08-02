# push-commercial-env.ps1
# Đẩy lên Vercel Production các biến: COMMERCIAL_AUTH, JWT/anon, admin panel, MAX_DEVICES.
# Yêu cầu: đã `vercel link` trong thư mục server, đã điền server/commercial.env.local
#
#   cd server
#   copy commercial.env.local.example commercial.env.local
#   # sửa file: dán JWT Secret + anon key
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\push-commercial-env.ps1

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$serverRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $serverRoot

# Dùng .cmd thay vì vercel.ps1 để tránh edge case PowerShell; CI + non-interactive tránh prompt treo.
$env:CI = "true"
$vercelExe = (Get-Command vercel.cmd -ErrorAction SilentlyContinue).Source
if (-not $vercelExe) {
    Write-Error "vercel.cmd not found on PATH. Install Vercel CLI (npm i -g vercel)."
    exit 1
}

$localPath = Join-Path $serverRoot "commercial.env.local"
if (-not (Test-Path $localPath)) {
    Write-Error "Missing $localPath - copy commercial.env.local.example to commercial.env.local and fill JWT + anon."
    exit 1
}

function Parse-EnvFile([string]$path) {
    $d = @{}
    Get-Content -LiteralPath $path -Encoding UTF8 | ForEach-Object {
        $line = $_.Trim()
        if ($line -eq "" -or $line.StartsWith("#")) { return }
        $eq = $line.IndexOf("=")
        if ($eq -lt 1) { return }
        $k = $line.Substring(0, $eq).Trim()
        $v = $line.Substring($eq + 1).Trim()
        if ($v.Length -ge 2 -and $v.StartsWith('"') -and $v.EndsWith('"')) {
            $v = $v.Substring(1, $v.Length - 2)
        }
        $d[$k] = $v
    }
    return $d
}

$cfg = Parse-EnvFile $localPath
$jwt = [string]$cfg["SUPABASE_JWT_SECRET"]
$anon = [string]$cfg["SUPABASE_ANON_KEY"]
if ([string]::IsNullOrWhiteSpace($jwt) -or [string]::IsNullOrWhiteSpace($anon)) {
    Write-Error "commercial.env.local: SUPABASE_JWT_SECRET and SUPABASE_ANON_KEY must be non-empty."
    exit 1
}

function RandSecret([int]$len) {
    $chars = [char[]](([char[]]([char]'A'..[char]'Z')) + ([char[]]([char]'a'..[char]'z')) + ([char[]]([char]'0'..[char]'9')))
    -join ((1..$len) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
}

$adminSecret = RandSecret 44
if ($adminSecret.Length -lt 32) { Write-Error "RNG failed"; exit 1 }

function Push-Env([string]$name, [string]$value, [switch]$Sensitive) {
    $argList = @(
        "env", "add", $name, "production",
        "--value", $value,
        "--yes", "--force",
        "--non-interactive", "--no-color"
    )
    if ($Sensitive) { $argList += "--sensitive" }
    Write-Host ">> $name (Vercel API, ~5-30s)..."
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    $null = & $vercelExe @argList 2>&1
    $code = $LASTEXITCODE
    $ErrorActionPreference = $prev
    if ($code -ne 0) {
        throw "vercel env add failed: $name (exit $code)"
    }
}

Write-Host ">> Pushing env to Vercel Production (COMMERCIAL + admin)..."
Push-Env "COMMERCIAL_AUTH" "true"
Push-Env "SUPABASE_JWT_SECRET" $jwt -Sensitive
Push-Env "SUPABASE_ANON_KEY" $anon -Sensitive
Push-Env "MAX_DEVICES_PER_USER" "1"
Push-Env "ELEVENFLOW_ADMIN_SECRET" $adminSecret -Sensitive
Push-Env "ELEVENFLOW_ADMIN_USERNAME" "admin"
Push-Env "ELEVENFLOW_ADMIN_PASSWORD" "veo3" -Sensitive

Write-Host ""
Write-Host "OK. Save ELEVENFLOW_ADMIN_SECRET (shown once):"
Write-Host $adminSecret
Write-Host ""
Write-Host "Next: vercel deploy --prod"
