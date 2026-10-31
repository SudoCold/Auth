[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$authProject = Join-Path $PSScriptRoot '..\src\Auth.Api\Auth.Api.csproj'
$authDevelopmentKey = [Environment]::GetEnvironmentVariable('Jwt__SigningKey', 'Process')

if ([string]::IsNullOrWhiteSpace($authDevelopmentKey) -or
    [Text.Encoding]::UTF8.GetByteCount($authDevelopmentKey) -lt 32) {
    # Capture secret output; never print the stored key or other user-secrets.
    $authSecretOutput = @(& dotnet user-secrets list --project $authProject --json)
    if ($LASTEXITCODE -ne 0) { throw 'Could not read development user-secrets. Check that the .NET 10 SDK is installed.' }
    $authSecretJson = ($authSecretOutput | Where-Object { $_ -notmatch '^\s*//' }) -join [Environment]::NewLine
    if ($authSecretJson.TrimStart().StartsWith('{')) {
        $authSecretValues = $authSecretJson | ConvertFrom-Json
        $authKeyProperty = $authSecretValues.PSObject.Properties['Jwt:SigningKey']
        if ($null -ne $authKeyProperty) { $authDevelopmentKey = [string]$authKeyProperty.Value }
    }

    if ([string]::IsNullOrWhiteSpace($authDevelopmentKey) -or
        [Text.Encoding]::UTF8.GetByteCount($authDevelopmentKey) -lt 32) {
        # The instance API works in both Windows PowerShell 5.1 and PowerShell 7.
        $authKeyBytes = New-Object byte[] 48
        $authRandom = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $authRandom.GetBytes($authKeyBytes) } finally { $authRandom.Dispose() }
        $authDevelopmentKey = [Convert]::ToBase64String($authKeyBytes)
        # Pass the key through stdin rather than exposing it in command-line arguments.
        @{ 'Jwt:SigningKey' = $authDevelopmentKey } | ConvertTo-Json -Compress |
            & dotnet user-secrets set --project $authProject
        if ($LASTEXITCODE -ne 0) { throw 'Could not save the development signing key.' }
        Write-Host 'Created and saved a random development signing key.'
    }
}

$authPreviousEnvironment = @{}
foreach ($authVariable in @('Jwt__SigningKey', 'DOTNET_ENVIRONMENT', 'ASPNETCORE_ENVIRONMENT')) {
    $authPreviousEnvironment[$authVariable] = [Environment]::GetEnvironmentVariable($authVariable, 'Process')
}
try {
    $env:Jwt__SigningKey = $authDevelopmentKey
    $env:DOTNET_ENVIRONMENT = 'Development'
    $env:ASPNETCORE_ENVIRONMENT = 'Development'
    Write-Host 'Starting the API in Development with a configured signing key.'
    & dotnet run --project $authProject --launch-profile https
    if ($LASTEXITCODE -ne 0) { throw "The API exited with code $LASTEXITCODE." }
}
finally {
    foreach ($authVariable in $authPreviousEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($authVariable, $authPreviousEnvironment[$authVariable], 'Process')
    }
}
