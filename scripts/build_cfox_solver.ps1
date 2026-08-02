# build_cfox_solver.ps1
# Compile cfox_captcha.py -> cfox_solver.exe bằng Nuitka.
# Nuitka compile Python -> C -> native binary (không decompile được).
#
# Output: build\bin\cfox_solver.exe
#
# Chạy: powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build_cfox_solver.ps1

$ErrorActionPreference = "Stop"
$projRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$scriptSrc = Join-Path $projRoot "internal\camoufoxbridge\embed\cfox_captcha.py"
$buildDir = Join-Path $projRoot "build\bin"
$nuitkaOut = Join-Path $projRoot "build\nuitka_out"

if (-not (Test-Path $scriptSrc)) {
    Write-Error "Khong tim thay $scriptSrc"
    exit 1
}

New-Item -ItemType Directory -Force -Path $buildDir | Out-Null
New-Item -ItemType Directory -Force -Path $nuitkaOut | Out-Null

Write-Host ">> Nuitka: cfox_captcha.py -> cfox_solver.exe"
Write-Host "   Source: $scriptSrc"
Write-Host "   Mode: onefile, low-memory, 1 job"

py -3 -m nuitka `
    --onefile `
    --output-filename=cfox_solver.exe `
    --output-dir=$nuitkaOut `
    --assume-yes-for-downloads `
    --jobs=1 `
    --low-memory `
    --nofollow-import-to=tkinter `
    --nofollow-import-to=unittest `
    --nofollow-import-to=test `
    --nofollow-import-to=setuptools `
    --nofollow-import-to=pip `
    --nofollow-import-to=numpy `
    --nofollow-import-to=PIL `
    --nofollow-import-to=cv2 `
    --nofollow-import-to=scipy `
    --nofollow-import-to=matplotlib `
    --nofollow-import-to=pandas `
    --nofollow-import-to=IPython `
    --nofollow-import-to=pytest `
    --nofollow-import-to=sphinx `
    --nofollow-import-to=docutils `
    --enable-plugin=anti-bloat `
    --windows-console-mode=attach `
    $scriptSrc

if ($LASTEXITCODE -ne 0) {
    Write-Error "Nuitka build failed!"
    exit 1
}

# Find output exe
$src = Get-ChildItem -Path $nuitkaOut -Filter "cfox_solver.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
if (-not $src -or -not (Test-Path $src)) {
    Write-Error "cfox_solver.exe not found in $nuitkaOut"
    exit 1
}

$dst = Join-Path $buildDir "cfox_solver.exe"
Copy-Item -Path $src -Destination $dst -Force

$size = (Get-Item $dst).Length / 1MB
Write-Host ""
Write-Host ("OK: cfox_solver.exe ({0:N1} MB) - Nuitka native" -f $size)
Write-Host "   Path: $dst"
