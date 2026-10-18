# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for Sentinel Agent — Windows .exe one-file
# Usage local (Windows):
#   pip install pyinstaller
#   pyinstaller sentinel-agent.spec
# Output: dist/SentinelAgent.exe (one-file, ~15-20 MB)

block_cipher = None

a = Analysis(
    ['sentinel_agent/__main__.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('config.example.json', '.'),  # included as example
    ],
    hiddenimports=[
        'psutil',
        'requests',
        'win32evtlog',      # pywin32, may be missing on non-Windows build — ok
        'win32evtlogutil',
        'win32con',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# Filter out missing win32 modules gracefully on Linux builder
# PyInstaller will warn but not fail

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='SentinelAgent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # True = console app (voir logs), set False pour windowed si besoin
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,  # ajouter 'assets/icon.ico' si dispo
)

# Optionnel: dossier dist avec one-dir (plus rapide au démarrage, moins 1 exe)
# Pour one-dir, remplace EXE+COLLECT:
# coll = COLLECT(exe, a.binaries, ... name='SentinelAgent')
