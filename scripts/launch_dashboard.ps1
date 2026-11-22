<#
.SYNOPSIS
  Lanzador del panel web de MCP Maltego (uso local en Windows).

.DESCRIPTION
  - Si el panel ya responde en http://127.0.0.1:<Port>/, intenta traer al frente la ventana del navegador
    cuyo título es el del panel; si no la encuentra, abre la URL en el navegador por defecto.
  - Si no está levantado, arranca `uv run maltegoctl dashboard --no-browser` en segundo plano (ventana oculta,
    log en ~/.maltego-mcp/runtime/dashboard.log), espera a que responda y abre el navegador.
  No lee ni muestra secretos: las claves siguen en ~/.maltego-mcp/.env y la contraseña del panel en
  ~/.maltego-mcp/dashboard_auth.json (hash PBKDF2).
#>
param(
    [int]$Port = 8000,
    [int]$TimeoutSeconds = 90
)

$ErrorActionPreference = 'Stop'
$Url = "http://127.0.0.1:$Port/"
$TitlePrefix = 'MCP Maltego'
$RepoRoot = Split-Path -Parent $PSScriptRoot

function Test-Dashboard {
    try {
        $resp = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 3
        return ($resp.StatusCode -eq 200 -and $resp.Content -match [regex]::Escape($TitlePrefix))
    } catch {
        return $false
    }
}

function Show-Message([string]$Text) {
    Add-Type -AssemblyName PresentationFramework
    [void][System.Windows.MessageBox]::Show($Text, 'MCP Maltego')
}

function Open-OrFocus {
    # Los navegadores muestran en el título de la ventana el título de la pestaña activa.
    $shell = New-Object -ComObject WScript.Shell
    $win = Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.MainWindowHandle -ne 0 -and $_.MainWindowTitle -like "$TitlePrefix*" } |
        Select-Object -First 1
    if ($win -and $shell.AppActivate($win.Id)) {
        return
    }
    Start-Process $Url
}

if (Test-Dashboard) {
    Open-OrFocus
    exit 0
}

# Puerto ocupado por otro programa: no se arranca una segunda instancia.
$busy = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($busy) {
    Show-Message "El puerto $Port está ocupado por otro proceso (PID $($busy[0].OwningProcess)) que no es el panel de MCP Maltego."
    exit 1
}

$uv = (Get-Command uv -ErrorAction SilentlyContinue).Source
if (-not $uv) {
    $fallbackUv = Join-Path $HOME '.local\bin\uv.exe'
    if (Test-Path $fallbackUv) {
        $uv = $fallbackUv
    }
}
if (-not $uv) {
    Show-Message 'No se encuentra uv en el PATH. Instálalo o abre una terminal en el repositorio y ejecuta: uv run maltegoctl dashboard'
    exit 1
}

$homeDir = if ($env:MALTEGO_MCP_HOME) { $env:MALTEGO_MCP_HOME } else { Join-Path $HOME '.maltego-mcp' }
if (-not $env:MALTEGO_MCP_ALLOW_ACTIVE) { $env:MALTEGO_MCP_ALLOW_ACTIVE = '1' }
if (-not $env:MALTEGO_MCP_MODE) { $env:MALTEGO_MCP_MODE = 'active' }
$logDir = Join-Path $homeDir 'runtime'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$log = Join-Path $logDir 'dashboard.log'
$errLog = Join-Path $logDir 'dashboard.err.log'

Start-Process -FilePath $uv `
    -ArgumentList @('run', 'maltegoctl', 'dashboard', '--port', "$Port", '--no-browser') `
    -WorkingDirectory $RepoRoot `
    -WindowStyle Hidden `
    -RedirectStandardOutput $log `
    -RedirectStandardError $errLog | Out-Null

$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 800
    if (Test-Dashboard) {
        Start-Process $Url
        exit 0
    }
}

Show-Message "El panel no respondió en $TimeoutSeconds s. Revisa el log: $errLog"
exit 1

