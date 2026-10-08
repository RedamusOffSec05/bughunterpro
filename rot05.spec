# PyInstaller spec for rot05.exe
# Build: pyinstaller rot05.spec
# Output: dist/rot05.exe  (~35-60 MB single file)

block_cipher = None

a = Analysis(
    ['red_offensive_team_05.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        # colorama
        'colorama',
        'colorama.ansitowin32',
        # cryptography
        'cryptography',
        'cryptography.fernet',
        'cryptography.hazmat',
        'cryptography.hazmat.backends',
        'cryptography.hazmat.backends.openssl',
        'cryptography.hazmat.primitives',
        'cryptography.hazmat.primitives.hashes',
        'cryptography.hazmat.primitives.kdf.pbkdf2',
        # impacket core
        'impacket',
        'impacket.krb5',
        'impacket.krb5.asn1',
        'impacket.krb5.ccache',
        'impacket.krb5.kerberosv5',
        'impacket.krb5.types',
        'impacket.krb5.crypto',
        'impacket.krb5.pac',
        'impacket.ntlm',
        'impacket.smb',
        'impacket.smb3',
        'impacket.smbconnection',
        'impacket.nmb',
        'impacket.uuid',
        'impacket.structure',
        'impacket.dcerpc',
        'impacket.dcerpc.v5',
        'impacket.dcerpc.v5.drsuapi',
        'impacket.dcerpc.v5.dtypes',
        'impacket.dcerpc.v5.epm',
        'impacket.dcerpc.v5.lsat',
        'impacket.dcerpc.v5.lsad',
        'impacket.dcerpc.v5.nrpc',
        'impacket.dcerpc.v5.rpcrt',
        'impacket.dcerpc.v5.samr',
        'impacket.dcerpc.v5.scmr',
        'impacket.dcerpc.v5.transport',
        'impacket.dcerpc.v5.wkst',
        'impacket.ldap',
        'impacket.ldap.ldap',
        'impacket.ldap.ldapasn1',
        'impacket.examples',
        'impacket.examples.utils',
        'impacket.examples.secretsdump',
        # dns
        'dns',
        'dns.resolver',
        'dns.name',
        'dns.rdatatype',
        # stdlib that PyInstaller can miss
        'cmd',
        'getpass',
        'concurrent.futures',
        'xml.etree.ElementTree',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # weasyprint needs libpango/libcairo — not available on bare Windows
    # the script already falls back gracefully when it's missing
    excludes=['weasyprint', 'gi', 'gtk', 'pango', 'cairo'],
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
    name='rot05',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,         # compress — requires upx.exe on PATH (optional)
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,     # pentesting tool — keep terminal window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # icon='assets/rot05.ico',   # uncomment if you add an .ico file
)
