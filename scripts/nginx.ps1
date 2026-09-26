<#
.SYNOPSIS
  Manage the local nginx reverse proxy for ArcRadar (http://localhost:8080 -> Next.js on :3000).
.EXAMPLE
  powershell -File scripts/nginx.ps1 test     # validate deploy/nginx/nginx.conf
  powershell -File scripts/nginx.ps1 start
  powershell -File scripts/nginx.ps1 reload
  powershell -File scripts/nginx.ps1 stop
#>
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [ValidateSet('test', 'start', 'stop', 'reload')]
  [string]$Action
)

$ErrorActionPreference = 'Stop'

$nginx = (Get-Command nginx -ErrorAction SilentlyContinue).Source
if (-not $nginx) {
  throw 'nginx was not found on PATH. Install it with "winget install nginxinc.nginx" and reopen the terminal.'
}

$root = Split-Path $PSScriptRoot
$conf = Join-Path $root 'deploy\nginx\nginx.conf'
$prefix = Join-Path $root 'deploy\nginx\runtime'
# nginx does not create its parent directories itself.
foreach ($dir in 'logs', 'temp') {
  New-Item -ItemType Directory -Force -Path (Join-Path $prefix $dir) | Out-Null
}

$common = @('-p', $prefix, '-c', $conf)

switch ($Action) {
  'test'   { & $nginx @common -t }
  'reload' { & $nginx @common -s reload }
  'stop'   { & $nginx @common -s quit }
  'start'  {
    & $nginx @common -t
    if ($LASTEXITCODE -ne 0) { throw 'nginx configuration test failed; not starting.' }
    $quoted = $common | ForEach-Object { '"' + $_ + '"' }
    Start-Process -FilePath $nginx -ArgumentList $quoted -WindowStyle Hidden
    Write-Host 'nginx started: http://localhost:8080 (proxying to http://127.0.0.1:3000)'
  }
}
