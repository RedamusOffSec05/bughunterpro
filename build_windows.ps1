# build_windows.ps1 — Build rot05.exe on your local Windows 11 machine
# Run from the repo root in an elevated PowerShell terminal:
#   Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
#   .\build_windows.ps1

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║        ROT05 Windows EXE Builder                  ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ── Check Python ─────────────────────────────────────────────────────────
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "Python not found. Install Python 3.10+ from https://python.org"
    exit 1
}
$pyver = python --version
Write-Host "[+] $pyver" -ForegroundColor Green

# ── Upgrade pip ──────────────────────────────────────────────────────────
Write-Host "[*] Upgrading pip…" -ForegroundColor Yellow
python -m pip install --upgrade pip --quiet

# ── Install build dependencies ───────────────────────────────────────────
Write-Host "[*] Installing Python dependencies…" -ForegroundColor Yellow
pip install --quiet pyinstaller `
    colorama `
    cryptography `
    requests `
    dnspython `
    beautifulsoup4 `
    impacket `
    certipy-ad

if ($LASTEXITCODE -ne 0) {
    Write-Error "Dependency install failed."
    exit 1
}

# ── Optional: UPX for compression ────────────────────────────────────────
$upxPath = "$env:ProgramFiles\UPX\upx.exe"
if (-not (Test-Path $upxPath)) {
    Write-Host "[!] UPX not found — exe won't be compressed (still works fine)" -ForegroundColor Yellow
    Write-Host "    Download from https://upx.github.io if you want a smaller file"
}

# ── Clean previous build ─────────────────────────────────────────────────
if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
if (Test-Path "build") { Remove-Item -Recurse -Force "build" }

# ── Build ─────────────────────────────────────────────────────────────────
Write-Host "[*] Running PyInstaller…" -ForegroundColor Yellow
pyinstaller rot05.spec --noconfirm

if ($LASTEXITCODE -ne 0) {
    Write-Error "PyInstaller failed — check output above."
    exit 1
}

# ── Result ───────────────────────────────────────────────────────────────
$exePath = "dist\rot05.exe"
if (Test-Path $exePath) {
    $sizeMB = [Math]::Round((Get-Item $exePath).Length / 1MB, 1)
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║  Build complete!                                   ║" -ForegroundColor Green
    Write-Host "║  dist\rot05.exe  ($sizeMB MB)                        ║" -ForegroundColor Green
    Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "Usage examples:" -ForegroundColor Cyan
    Write-Host "  .\dist\rot05.exe                                # interactive shell"
    Write-Host "  .\dist\rot05.exe -t 10.10.10.10 --enum"
    Write-Host "  .\dist\rot05.exe -t 10.10.10.10 -d lab.local -u admin -P --full"
    Write-Host "  .\dist\rot05.exe -t 10.10.10.10 --scan-cves"
    Write-Host ""
    Write-Host "Note: nmap must be installed separately on Windows." -ForegroundColor Yellow
    Write-Host "      Download from https://nmap.org/download.html" -ForegroundColor Yellow
    Write-Host "      Linux-only tools (smbclient, enum4linux) are skipped automatically." -ForegroundColor Yellow
} else {
    Write-Error "Build failed — dist\rot05.exe not found."
    exit 1
}
