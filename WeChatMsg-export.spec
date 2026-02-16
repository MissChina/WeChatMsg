# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = ['pymem', 'pymem.process', 'yara', 'psutil', 'win32api', 'win32process', 'win32com.client', 'pythoncom', 'Crypto.Cipher.AES', 'Crypto.Protocol.KDF', 'Crypto.Hash.SHA512', 'Crypto.Hash.HMAC', 'google.protobuf.json_format', 'google.protobuf.descriptor', 'google.protobuf.descriptor_pool', 'google.protobuf.symbol_database', 'google.protobuf.reflection', 'zstandard', 'lz4.block', 'aiofiles', 'xmltodict', 'lxml.etree', 'openpyxl', 'docx', 'pysilk', 'PIL.Image', 'bs4', 'soupsieve']
hiddenimports += collect_submodules('wxManager')
hiddenimports += collect_submodules('exporter')
hiddenimports += collect_submodules('google.protobuf')
hiddenimports += collect_submodules('docx')


a = Analysis(
    ['example\\export_all.py'],
    pathex=['.'],
    binaries=[],
    datas=[('wxManager', 'wxManager'), ('exporter', 'exporter')],
    hiddenimports=hiddenimports,
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
    name='WeChatMsg-export',
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
