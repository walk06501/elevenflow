# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['D:\\ElevenLabsTTSApp.exe_extracted\\elevenflow\\internal\\camoufoxbridge\\embed\\cfox_captcha.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=['camoufox', 'camoufox.pkgman', 'playwright', 'playwright.sync_api', 'playwright._impl', 'playwright._impl._api_types'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='cfox_solver',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
