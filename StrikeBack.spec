# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[('data/yara_rules', 'data/yara_rules'), ('web', 'web'), ('ui', 'ui')],
    hiddenimports=['cryptography', 'cryptography.hazmat.primitives.ciphers.aead', 'cryptography.hazmat.primitives.kdf.pbkdf2', 'cryptography.hazmat.primitives.asymmetric.ec', 'cryptography.x509', 'pyotp', 'scapy', 'scapy.all', 'nmap', 'pywifi', 'comtypes', 'tools.network_scanner', 'tools.traffic_analyzer', 'tools.wifi_auditor', 'tools.password_auditor', 'tools.forensic_collector', 'PyQt6', 'PyQt6.QtCore', 'PyQt6.QtWidgets', 'PyQt6.QtGui', 'ui.main_window'],
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
    name='StrikeBack',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['StrikeBack.ico'],
)
