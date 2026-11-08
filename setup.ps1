$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
Write-Host "[Axon] Checking Python..." -ForegroundColor Green
python --version
if ($LASTEXITCODE -ne 0) { throw "Python 3.10+ is required. Install from https://www.python.org/downloads/" }
if (-not (Test-Path ".venv")) { python -m venv .venv }
& ".\.venv\Scripts\python.exe" -m pip install --upgrade pip
& ".\.venv\Scripts\python.exe" -m pip install -r requirements.txt
Write-Host "Dependencies installed." -ForegroundColor Green
Write-Host "Install Npcap from https://npcap.com/ for live capture."
Write-Host "Then run .\run.ps1. Administrator permissions may be required for live capture."
