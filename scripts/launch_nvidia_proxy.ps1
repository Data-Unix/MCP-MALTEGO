<#
.SYNOPSIS
  Lanza el Proxy Local de NVIDIA NIM (LiteLLM) en el puerto 4000.
.DESCRIPTION
  Verifica si el proxy ya está en ejecución antes de lanzarlo para evitar colisiones de puerto.
#>

$port = 4000
$configFile = "$HOME\.gemini\config\nvidia_proxy.yaml"

if (-not (Test-Path $configFile)) {
    Write-Error "No se encontro el archivo de configuracion en $configFile"
    exit 1
}

$activeConn = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue

if ($activeConn) {
    Write-Host "[NVIDIA NIM Proxy] El proxy ya esta escuchando en http://127.0.0.1:$port (PID: $($activeConn.OwningProcess))" -ForegroundColor Green
    exit 0
}

Write-Host "[NVIDIA NIM Proxy] Iniciando servidor LiteLLM en http://127.0.0.1:$port..." -ForegroundColor Cyan
$litellmBin = "$HOME\.local\bin\litellm.exe"
if (Test-Path $litellmBin) {
    & $litellmBin --config $configFile --port $port --host 127.0.0.1
} else {
    uv run --with "litellm[proxy]" litellm --config $configFile --port $port --host 127.0.0.1
}

