# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['setup_installer.py'],
    pathex=[],
    binaries=[],
    datas=[('requirements.txt', '.'), ('StrikeBack.png', '.')],
    hiddenimports=['rich'],
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
    name='Setup_StrikeBack',
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
    icon=['StrikeBack.ico'],
)
