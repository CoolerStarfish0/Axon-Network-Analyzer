$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) { Write-Host "Run .\setup.ps1 first." -ForegroundColor Yellow; exit 1 }
& $python app.py
