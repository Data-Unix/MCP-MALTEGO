<#
.SYNOPSIS
  Selector y gestor de modos operativos para el Anillo de Privacidad de Mullvad (MCP Maltego).

.DESCRIPTION
  Permite alternar de forma segura e inmediata entre:
  - Modo 1: Rapido (Rápido y Seguro)
      * Salto único directo (baja latencia, alto ancho de banda)
      * Servidor de salida 100 % en propiedad de Mullvad (por defecto de-dus-wg-101)
      * Lockdown Mode activo (anti-fugas en kernel WFP)
      * DAITA y Resistencia Cuántica apagadas para velocidad óptima
      * Filtro DNS contra anuncios y rastreadores

  - Modo 2: Paranoico (Máxima Privacidad y Anti-Vigilancia)
      * Multi-hop con salto de entrada y de salida 100 % propios (nunca alquilados)
      * DAITA (Defense Against AI-guided Traffic Analysis - padding y tráfico de cobertura)
      * Resistencia Cuántica (intercambio de claves post-cuántico Kyber)
      * Lockdown Mode activo (fail-closed absoluto)
      * Filtro DNS reforzado (anuncios + rastreadores + malware)
      * Túnel dividido (split-tunnel) desactivado y auto-connect forzado

.EXAMPLE
  .\scripts\set_mullvad_mode.ps1 -Mode Rapido -Apply
  .\scripts\set_mullvad_mode.ps1 -Mode Paranoico -Apply
  .\scripts\set_mullvad_mode.ps1 -Status
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('Rapido', 'Paranoico', 'Status', '1', '2')]
    [string]$Mode = 'Status',

    [string]$ExitRelay = 'de-dus-wg-101',
    [string]$EntryRelay = 'se-sto-wg-001',

    [switch]$Status,
    [switch]$Apply
)

if ($Status) {
    $Mode = 'Status'
}

$ErrorActionPreference = 'Stop'
$MullvadCli = Join-Path $env:ProgramFiles 'Mullvad VPN\resources\mullvad.exe'

if (-not (Test-Path -LiteralPath $MullvadCli)) {
    Write-Error "No se encontró el ejecutable de Mullvad en: $MullvadCli"
    exit 1
}

function Invoke-Mv {
    param([string[]]$CommandArgs)
    if ($Apply) {
        $p = Start-Process -FilePath $MullvadCli -ArgumentList $CommandArgs -NoNewWindow -Wait -PassThru
        if ($p.ExitCode -ne 0) {
            throw "El comando 'mullvad $($CommandArgs -join ' ')' falló con código $($p.ExitCode)."
        }
    } else {
        Write-Host "  [SIMULACIÓN] mullvad $($CommandArgs -join ' ')" -ForegroundColor DarkGray
    }
}

function Show-Status {
    Write-Host "`n=== ESTADO ACTUAL DEL ANILLO MULLVAD ===" -ForegroundColor Cyan
    & $MullvadCli status -v
    Write-Host "`n--- REGLAS DE ENTRADA Y SALIDA (RELAYS) ---" -ForegroundColor DarkCyan
    & $MullvadCli relay get
    Write-Host "`n--- OPCIONES DE TÚNEL (DAITA / CUÁNTICA) ---" -ForegroundColor DarkCyan
    & $MullvadCli tunnel get
    Write-Host "`n--- FILTRO DE CONTENIDO DNS ---" -ForegroundColor DarkCyan
    & $MullvadCli dns get
    Write-Host "`n--- MODO DE BLOQUEO (LOCKDOWN FAIL-CLOSED) ---" -ForegroundColor DarkCyan
    & $MullvadCli lockdown-mode get
    Write-Host ""
}

if ($Mode -eq 'Status') {
    Show-Status
    exit 0
}

if ($Mode -in @('Rapido', '1')) {
    Write-Host "`n[+] CONFIGURANDO MODO 1: RAPIDO Y SEGURO" -ForegroundColor Green
    Write-Host "Objetivo: Salto unico directo + Servidor propio + Lockdown activo (baja latencia)" -ForegroundColor Gray

    Invoke-Mv @('relay', 'set', 'ownership', 'owned')
    Invoke-Mv @('relay', 'set', 'multihop', 'off')
    Invoke-Mv @('relay', 'set', 'location', 'de', 'dus', $ExitRelay)
    Invoke-Mv @('tunnel', 'set', 'daita', 'off')
    Invoke-Mv @('tunnel', 'set', 'quantum-resistant', 'off')
    Invoke-Mv @('dns', 'set', 'default', '--block-ads', '--block-trackers')
    Invoke-Mv @('split-tunnel', 'set', 'off')
    Invoke-Mv @('auto-connect', 'set', 'on')
    Invoke-Mv @('lockdown-mode', 'set', 'on')

    if ($Apply) {
        Write-Host "Reconectando tunel en Modo Rapido..." -ForegroundColor Yellow
        Invoke-Mv @('reconnect', '--wait')
        Write-Host "Modo Rapido y Seguro APLICADO con exito." -ForegroundColor Green
        Show-Status
    } else {
        Write-Host "`n[AVISO] Se ejecuto en modo simulacion. Agrega -Apply para aplicar los cambios en Mullvad." -ForegroundColor Yellow
    }
}
elseif ($Mode -in @('Paranoico', '2')) {
    Write-Host "`n[+] CONFIGURANDO MODO 2: PARANOICO (MAXIMA PRIVACIDAD)" -ForegroundColor Magenta
    Write-Host "Objetivo: Multi-hop propio + DAITA + Resistencia Cuantica + Lockdown activo" -ForegroundColor Gray

    Invoke-Mv @('relay', 'set', 'ownership', 'owned')
    Invoke-Mv @('relay', 'set', 'multihop', 'on')
    Invoke-Mv @('relay', 'set', 'entry', 'location', 'se', 'sto', $EntryRelay)
    Invoke-Mv @('relay', 'set', 'location', 'de', 'dus', $ExitRelay)
    Invoke-Mv @('tunnel', 'set', 'daita', 'on')
    Invoke-Mv @('tunnel', 'set', 'quantum-resistant', 'on')
    Invoke-Mv @('dns', 'set', 'default', '--block-ads', '--block-trackers', '--block-malware')
    Invoke-Mv @('split-tunnel', 'set', 'off')
    Invoke-Mv @('auto-connect', 'set', 'on')
    Invoke-Mv @('lockdown-mode', 'set', 'on')

    if ($Apply) {
        Write-Host "Reconectando tunel en Modo Paranoico..." -ForegroundColor Yellow
        Invoke-Mv @('reconnect', '--wait')
        Write-Host "Modo Paranoico APLICADO con exito." -ForegroundColor Green
        Show-Status
    } else {
        Write-Host "`n[AVISO] Se ejecuto en modo simulacion. Agrega -Apply para aplicar los cambios en Mullvad." -ForegroundColor Yellow
    }
}
