# -*- mode: python ; coding: utf-8 -*-
"""
CTF Web Toolkit - PyInstaller Spec File
构建单文件可执行程序（macOS / Windows / Linux）

macOS:  pyinstaller ctf_toolkit.spec  →  dist/ctf-toolkit
Windows: pyinstaller ctf_toolkit.spec  →  dist/ctf-toolkit.exe
"""

import sys
import os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# ── 自动收集所有子模块 ────────────────────────
hidden_imports = (
    collect_submodules('core') +
    collect_submodules('offensive') +
    collect_submodules('defensive') +
    [
        'colorama',
        'requests',
        'urllib3',
        'charset_normalizer',
        'certifi',
        'idna',
        'Crypto',
        'Crypto.Cipher',
        'Crypto.Cipher.AES',
        'Crypto.Util',
        'Crypto.Util.Padding',
        'readline',
    ]
)

# ── 包含 payloads 字典目录 ─────────────────────
datas = [
    ('payloads', 'payloads'),
]

a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'pandas',
              'scipy', 'PIL', 'cv2', 'torch'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='ctf-toolkit',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,          # CLI 工具保持控制台模式
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,      # None = 当前架构；'universal2' = Fat Binary (仅 macOS)
    codesign_identity=None,
    entitlements_file=None,
    # Windows 图标 (可选)
    # icon='assets/icon.ico',
)
