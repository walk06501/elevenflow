# pack-release-camoufox.ps1
# Build ElevenFlow bản Camoufox:
#   1. Compile cfox_captcha.py -> cfox_solver.exe (PyInstaller)
#   2. Wails build -tags camoufox -> ElevenFlow-Camoufox.exe
#   3. ZIP: exe + cfox_solver.exe + ffmpeg
#
# User không cần cài Python — cfox_solver.exe chạy standalone.
# Camoufox browser tự tải lần đầu (~100MB).
#
# Chạy:
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\pack-release-camoufox.ps1

$ErrorActionPreference = "Stop"
$projRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $projRoot

# ── Đọc version ──────────────────────────────────────────────────────────────
$versionFile = Join-Path $projRoot "internal\buildinfo\version.go"
$verMatch = Select-String -Path $versionFile -Pattern 'AppVersion\s*=\s*"([^"]+)"'
if (-not $verMatch) {
    Write-Error "Khong doc duoc AppVersion"
    exit 1
}
$appVersion = $verMatch.Matches[0].Groups[1].Value
Write-Host ">> AppVersion = $appVersion"

# ── Step 1: Build cfox_solver.exe ────────────────────────────────────────────
Write-Host ""
Write-Host "═══ STEP 1: Build cfox_solver.exe (PyInstaller) ═══"
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build_cfox_solver.ps1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$solverExe = Join-Path $projRoot "build\bin\cfox_solver.exe"
if (-not (Test-Path $solverExe)) {
    Write-Error "cfox_solver.exe not built"
    exit 1
}

# ── Step 2: Wails build ─────────────────────────────────────────────────────
Write-Host ""
Write-Host "═══ STEP 2: Wails build -tags camoufox ═══"
wails build -tags camoufox -ldflags="-s -w" -trimpath
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$bin = Join-Path $projRoot "build\bin"
$exe = Join-Path $bin "elevenflow.exe"
if (-not (Test-Path $exe)) {
    Write-Error "elevenflow.exe not found"
    exit 1
}

# ── Dọn build\bin (giữ exe + cfox_solver.exe) ───────────────────────────────
Write-Host ">> clean build\bin"
Get-ChildItem -Path $bin -Force | Where-Object {
    $_.Name -notin @("elevenflow.exe", "cfox_solver.exe")
} | ForEach-Object {
    Write-Host "   remove: $($_.Name)"
    Remove-Item -Recurse -Force $_.FullName
}

# ── Copy ffmpeg ──────────────────────────────────────────────────────────────
$ffmpegSrc = Join-Path $projRoot "ffmpeg"
$ffmpegDst = Join-Path $bin "ffmpeg"
if (Test-Path $ffmpegSrc) {
    Write-Host ">> copy ffmpeg"
    Copy-Item -Path $ffmpegSrc -Destination $ffmpegDst -Recurse -Force
}

# ── Đổi tên exe ──────────────────────────────────────────────────────────────
$exePublished = Join-Path $bin "ElevenFlow-Camoufox-$appVersion.exe"
if (Test-Path $exePublished) { Remove-Item -Force $exePublished }
Rename-Item -LiteralPath $exe -NewName (Split-Path $exePublished -Leaf)

$mainSize = (Get-Item $exePublished).Length / 1MB
$solverSize = (Get-Item $solverExe).Length / 1MB
Write-Host ('{0} ({1:N1} MB)' -f (Split-Path $exePublished -Leaf), $mainSize)
Write-Host ('cfox_solver.exe ({0:N1} MB)' -f $solverSize)

# ── Step 3: ZIP ──────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "═══ STEP 3: ZIP ═══"
$dist = Join-Path $projRoot "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null
$zip = Join-Path $dist "ElevenFlow-Camoufox-windows-amd64.zip"
if (Test-Path $zip) { Remove-Item -Force $zip }

$zipPaths = @($exePublished, $solverExe)
if (Test-Path $ffmpegDst) { $zipPaths += $ffmpegDst }

Write-Host ">> Compress-Archive -> $zip"
Compress-Archive -LiteralPath $zipPaths -DestinationPath $zip -CompressionLevel Optimal

$zipInfo = Get-Item $zip
Write-Host ""
Write-Host ('OK: {0} ({1:N1} MB)' -f $zip, ($zipInfo.Length / 1MB))
Write-Host ""
Write-Host "Noi dung ZIP:"
Write-Host "  ElevenFlow-Camoufox-$appVersion.exe  (app chinh)"
Write-Host "  cfox_solver.exe                       (giai captcha, dat canh exe)"
Write-Host "  ffmpeg/                               (xu ly audio)"
Write-Host ""
Write-Host "User chi can giai nen va chay. Khong can Python."
Write-Host "Camoufox browser tu tai lan dau (~100MB)."
