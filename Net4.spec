# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['C:\\Users\\drabc\\Desktop\\net4\\main.py'],
    pathex=[],
    binaries=[],
    datas=[('assets', 'assets'), ('src/resources', 'resources')],
    hiddenimports=['scapy.contrib.http', 'matplotlib.backends.backend_qtagg'],
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
    name='Net4',
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
    icon=['C:\\Users\\drabc\\Desktop\\net4\\assets\\icons\\app_icon.png'],
)
