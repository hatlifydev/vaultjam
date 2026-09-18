# -*- mode: python ; coding: utf-8 -*-
# Empaquetado: .\.venv\Scripts\pyinstaller.exe vaultjam.spec
#
# Notas de seguridad del empaquetado:
#  - console=False: sin consola, nada de stdout/stderr con datos sensibles.
#  - Modo onedir (carpeta): el modo onefile se autoextrae a %TEMP% en cada
#    arranque; es solo el código de la app (no secretos), pero onedir evita
#    escrituras innecesarias y arranca más rápido.
#  - Los hooks oficiales recogen los plugins de Qt (multimedia incluido) y
#    las DLL de ffmpeg que usa PyAV.

a = Analysis(
    ["run_app.py"],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=["av"],
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    exclude_binaries=True,
    name="VaultJam",
    debug=False,
    strip=False,
    upx=False,
    console=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="VaultJam",
)
