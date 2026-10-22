param(
    [string]$DataDirectory = "data",
    [string]$UiDirectory = "ui-dist",
    [string]$CertificateFile = "certificates\free.mower.work.crt",
    [string]$PrivateKeyFile = "certificates\free.mower.work.key"
)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
foreach ($TlsFile in @($CertificateFile, $PrivateKeyFile)) {
    if (-not (Test-Path -LiteralPath $TlsFile -PathType Leaf)) {
        throw "Certificate or private key not found: $TlsFile"
    }
}
$SessionKey = Join-Path $DataDirectory "session-key.txt"
$AdminToken = Join-Path $DataDirectory "admin-token.txt"
& .\.relay-venv\Scripts\python.exe -m mower_relay_server.server `
    --work-dir $PSScriptRoot `
    --registry (Join-Path $DataDirectory "users.json") `
    --ui $UiDirectory --session-key-file $SessionKey --admin-token-file $AdminToken `
    --cert-file $CertificateFile --key-file $PrivateKeyFile
if ($LASTEXITCODE -ne 0) { throw "Mower relay exited: $LASTEXITCODE" }
