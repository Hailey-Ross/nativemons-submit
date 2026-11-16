# deploy.ps1: tests, builds the Linux binary, copies it and the service file to the server, restarts it.
# Reads VPS_HOST, VPS_USER and SSH_KEY from ..\.env (never committed). The first install is in README.md.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot
$cfg = @{}
Get-Content (Join-Path $root '.env') | Where-Object { $_ -match '^\s*([A-Z_]+)=(.+)$' } | ForEach-Object { $cfg[$Matches[1]] = $Matches[2].Trim() }
foreach ($need in 'VPS_HOST', 'VPS_USER', 'SSH_KEY') { if (-not $cfg[$need]) { throw "$need is missing from .env" } }
$target = "$($cfg.VPS_USER)@$($cfg.VPS_HOST)"
$ssh = @('-i', $cfg.SSH_KEY, '-o', 'BatchMode=yes')

Push-Location $root
try {
    go test ./...
    if ($LASTEXITCODE -ne 0) { throw 'tests failed: nothing deployed' }
    $env:GOOS = 'linux'; $env:GOARCH = 'amd64'; $env:CGO_ENABLED = '0'
    go build -trimpath -ldflags='-s -w' -o 'deploy\nativemons-submit' .
    if ($LASTEXITCODE -ne 0) { throw 'build failed' }
} finally {
    Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED -ErrorAction SilentlyContinue
    Pop-Location
}

scp @ssh (Join-Path $PSScriptRoot 'nativemons-submit') (Join-Path $PSScriptRoot 'nativemons-submit.service') "${target}:/tmp/"
ssh @ssh $target @'
set -e
sudo install -o root -g root -m 755 /tmp/nativemons-submit /opt/nativemons-submit/nativemons-submit
sudo install -o root -g root -m 644 /tmp/nativemons-submit.service /etc/systemd/system/nativemons-submit.service
rm -f /tmp/nativemons-submit /tmp/nativemons-submit.service
sudo systemctl daemon-reload
sudo systemctl restart nativemons-submit
sleep 1
curl -fsS http://127.0.0.1:8087/v1/health
'@
Remove-Item (Join-Path $PSScriptRoot 'nativemons-submit') -ErrorAction SilentlyContinue
'Deployed.'
