# pack-release.ps1
# Build production exe → đổi tên thành ElevenFlow-<AppVersion>.exe (đọc từ
# internal/buildinfo/version.go), chép ffmpeg → build\bin\ffmpeg, rồi zip vào
# dist\ElevenFlow-windows-amd64.zip.
# Phiên bản: đồng bộ wails.json info.productVersion + version.go (AppVersion).
# Đặt bộ ffmpeg (vd. gpt full build) tại: elevenflow\ffmpeg\  (cùng cấp wails.json).
#
# YÊU CẦU MÁY ĐÍCH (user nhận ZIP):
#   - Windows 10 (build 1809+) hoặc Windows 11
#   - Microsoft Edge WebView2 Runtime (đã bundled sẵn từ Win10 1909+, hoặc tự
#     update qua Edge). Tool sẽ báo lỗi nếu thiếu.
#   - KHÔNG cần Node, Python, Playwright, Firefox như bản cũ.
#
# Run từ project root:
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\pack-release.ps1

$ErrorActionPreference = "Stop"
$projRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $projRoot

$versionFile = Join-Path $projRoot "internal\buildinfo\version.go"
$verMatch = Select-String -Path $versionFile -Pattern 'AppVersion\s*=\s*"([^"]+)"' -ErrorAction SilentlyContinue
if (-not $verMatch) {
    Write-Error "Khong doc duoc AppVersion trong $versionFile"
    exit 1
}
$appVersion = $verMatch.Matches[0].Groups[1].Value
Write-Host ">> AppVersion = $appVersion (tu version.go)"

Write-Host ">> wails build (stripped, trimpath)"
# -ldflags="-s -w": strip symbol table + DWARF debug info → exe nhỏ hơn ~30-40%,
#                   giảm RAM linker (tránh OOM Go 1.26 khi build full module).
# -trimpath:        loại absolute path build machine khỏi binary (cleaner ZIP).
wails build -ldflags="-s -w" -trimpath
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$bin = Join-Path $projRoot "build\bin"
$exe = Join-Path $bin "elevenflow.exe"
if (-not (Test-Path $exe)) {
    Write-Error "Khong thay $exe -- kiem tra 'wails build'."
    exit 1
}

# Dọn build\bin: chỉ giữ lại elevenflow.exe (xóa các file dev, captcha-bridge cũ
# nếu còn sót lại từ bản trước).
Write-Host ">> clean build\bin"
Get-ChildItem -Path $bin -Force | Where-Object { $_.Name -ne "elevenflow.exe" } | ForEach-Object {
    Write-Host "   remove: $($_.Name)"
    Remove-Item -Recurse -Force $_.FullName
}

# Sao chép ffmpeg từ gốc repo (<projRoot>\ffmpeg) → cạnh exe (ứng dụng tìm .\ffmpeg\bin\ffmpeg.exe).
$ffmpegSrc = Join-Path $projRoot "ffmpeg"
$ffmpegDst = Join-Path $bin "ffmpeg"
if (Test-Path $ffmpegSrc) {
    Write-Host ">> copy ffmpeg -> build\bin\ffmpeg"
    Copy-Item -Path $ffmpegSrc -Destination $ffmpegDst -Recurse -Force
} else {
    Write-Warning "Khong thay $ffmpegSrc - ZIP chi co exe; ghep MP3 fallback neu khong co ffmpeg."
}

$exePublished = Join-Path $bin "ElevenFlow-$appVersion.exe"
if (Test-Path $exePublished) {
    Remove-Item -Force $exePublished
}
Write-Host ">> rename -> $(Split-Path $exePublished -Leaf)"
Rename-Item -LiteralPath $exe -NewName (Split-Path $exePublished -Leaf)

$exeInfo = Get-Item $exePublished
Write-Host ('   {0} size: {1:N2} MB' -f $exeInfo.Name, ($exeInfo.Length / 1MB))

$dist = Join-Path $projRoot "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null
$zip = Join-Path $dist "ElevenFlow-windows-amd64.zip"
if (Test-Path $zip) { Remove-Item -Force $zip }

$zipPaths = @($exePublished)
if (Test-Path $ffmpegDst) {
    $zipPaths += $ffmpegDst
    Write-Host ">> ZIP: exe + ffmpeg"
} else {
    Write-Host ">> ZIP: exe only"
}
Write-Host ">> Compress-Archive -> $zip"
Compress-Archive -LiteralPath $zipPaths -DestinationPath $zip -CompressionLevel Optimal

$zipInfo = Get-Item $zip
Write-Host ""
Write-Host ('OK: {0} ({1:N2} MB)' -f $zip, ($zipInfo.Length / 1MB))
Write-Host ('  --> Giai nen: ElevenFlow-{0}.exe va thu muc ffmpeg canh nhau.' -f $appVersion)
Write-Host '  --> Yeu cau: Win10/11 + Microsoft Edge WebView2 Runtime.'
