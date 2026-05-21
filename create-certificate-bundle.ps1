<#
.SYNOPSIS
    Exporta todos os certificados Trusted Root CA para um bundle PEM.

.DESCRIPTION
    Gera um arquivo .pem contendo todos os certificados da store LocalMachine\Root.
    Opcionalmente inclui CurrentUser\Root. Evita duplicatas por Thumbprint.

.EXAMPLE
    .\Create-CA-Bundle.ps1
    .\Create-CA-Bundle.ps1 -Output "C:\Temp\my-ca-bundle.pem" -IncludeCurrentUser

.NOTES
    Execute como Administrador se quiser acessar LocalMachine\Root.
#>

param(
    [string]$Output = "C:\Temp\ca-bundle.pem",
    [switch]$IncludeCurrentUser
)

function Ensure-Dir {
    param($path)
    $dir = [System.IO.Path]::GetDirectoryName($path)
    if (-not [string]::IsNullOrEmpty($dir) -and -not (Test-Path $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }
}

function To-PEM {
    param([byte[]]$raw)
    $b64 = [System.Convert]::ToBase64String($raw)
    # quebra em linhas de 64 caracteres
    $chunks = ($b64 -replace '.{64}',"$&`n")
    if (-not $chunks.EndsWith("`n")) { $chunks += "`n" }
    return "-----BEGIN CERTIFICATE-----`n$chunks-----END CERTIFICATE-----`n"
}

# Stores to read (LocalMachine\Root first)
$stores = @(
    @{ Location = 'LocalMachine'; Name = 'Root' }
)

if ($IncludeCurrentUser) {
    $stores += @{ Location = 'CurrentUser'; Name = 'Root' }
}

# Garantir pasta de saída
Ensure-Dir -path $Output

# Se existir bundle antigo, removemos (evita duplicatas ao rodar novamente)
if (Test-Path $Output) { Remove-Item -Path $Output -Force }

$seen = @{}  # track thumbprints to avoid dupes
$total = 0

foreach ($s in $stores) {
    try {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($s.Name, [System.Security.Cryptography.X509Certificates.StoreLocation]::$($s.Location))
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    } catch {
        Write-Warning "Não foi possível abrir store $($s.Location)\$($s.Name): $_"
        continue
    }

    foreach ($cert in $store.Certificates) {
        # somente certificados com chave pública (todos os certificados de CA)
        if (-not $cert) { continue }

        $thumb = $cert.Thumbprint
        if ($seen.ContainsKey($thumb)) { continue }
        $seen[$thumb] = $true

        try {
            $pem = To-PEM -raw $cert.RawData
            # Append em ASCII (PEM é texto ASCII)
            Add-Content -Path $Output -Value $pem -Encoding ASCII
            $total++
        } catch {
            Write-Warning "Erro exportando certificado $($cert.Subject) - $($_.Exception.Message)"
        }
    }

    $store.Close()
}

Write-Output "Bundle criado em: $Output"
Write-Output "Certificados exportados: $total"