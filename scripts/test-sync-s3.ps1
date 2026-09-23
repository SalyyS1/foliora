#requires -Version 7.4.1
<#
.SYNOPSIS
Native Windows, synthetic localhost PostgreSQL/MinIO backup and restore drill.
.DESCRIPTION
Requires preinstalled cargo/toolchain/dependency cache and caller-supplied pinned native tools.
Run from a non-elevated Windows session; PostgreSQL runs directly as the caller.
No installs, downloads, .env reads, global config edits, existing-store reuse, or deletions.
Artifacts (including synthetic fixture credentials) and a deterministic report stay in a new scratch directory.
Scratch and Cargo target volumes each need at least 256 MiB free. Default target: Repo/target.
Reuses the normal locked Cargo cache; a cold build requires substantially more space.
Child TEMP/TMP use RunDir/native-temp; the caller's environment is restored in finally.
.EXAMPLE
pwsh -File scripts/test-sync-s3.ps1 -PostgresBin C:/tools/pgsql/bin -MinioBinary C:/tools/minio.exe -McBinary C:/tools/mc.exe
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })][string]$PostgresBin,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$MinioBinary,
    [Parameter(Mandatory)][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$McBinary,
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })][string]$ScratchParent = [System.IO.Path]::GetTempPath(),
    [string]$CargoTargetDir = (Join-Path (Split-Path $PSScriptRoot -Parent) 'target')
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'This drill requires native Windows and PowerShell 7.4.1+' }
. "$PSScriptRoot/lib/sync-test-helpers.ps1"
$Repo = Split-Path $PSScriptRoot -Parent
$ScratchParent = (Resolve-Path -LiteralPath $ScratchParent).ProviderPath
$RunDir = Join-Path $ScratchParent ('foliora-s3-drill-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $RunDir # No -Force: never adopt an existing directory.
$Results = [ordered]@{}
$FailureReasons = [ordered]@{}
@('preflight', 'postgres', 'minio', 'restart', 'quota', 'migration', 'seed', 'build', 'inventory-live',
    'backup', 'restore', 'fixture-restored', 'inventory-restored', 'inventory-diff', 'api-ready',
    'stop-service', 'stop-postgres', 'stop-minio', 'stop-children', 'restore-environment') | ForEach-Object { $Results[$_] = 'SKIP' }
$OwnedProcesses = [System.Collections.Generic.List[object]]::new()
$EnvironmentBefore = @{}; $Pg = $null; $Minio = $null; $Api = $null
$failed = $false
Write-Host "Synthetic drill evidence: $RunDir"
Write-DrillReport
try {
    Invoke-DrillStep 'preflight' {
        $scratchDrive = [System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot($ScratchParent))
        if ($scratchDrive.AvailableFreeSpace -lt 256MB) { throw 'Scratch volume requires at least 256 MiB free' }
        $target = [System.IO.Path]::GetFullPath($CargoTargetDir, $Repo)
        $targetDrive = [System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot($target))
        if ($targetDrive.AvailableFreeSpace -lt 256MB) { throw 'Cargo target volume requires at least 256 MiB free; cold builds need more' }
        foreach ($directory in @('logs', 'mc', 'minio-data', 'minio-certs', 'native-temp', 'object-backup', 'object-restored')) {
            $null = New-Item -ItemType Directory -Path "$RunDir/$directory"
        }
        $script:PostgresBin = (Resolve-Path -LiteralPath $PostgresBin).ProviderPath
        $script:MinioBinary = (Resolve-Path -LiteralPath $MinioBinary).ProviderPath
        $script:McBinary = (Resolve-Path -LiteralPath $McBinary).ProviderPath
        foreach ($tool in @('initdb', 'postgres', 'pg_ctl', 'pg_isready', 'createdb', 'psql', 'pg_dump', 'pg_restore')) {
            if (-not (Test-Path -LiteralPath "$PostgresBin/$tool.exe" -PathType Leaf)) { throw "Missing PostgreSQL tool: $tool" }
        }
        $script:Cargo = Resolve-DrillExecutable 'cargo.exe'
        # Scope inherited storage settings, proxies, and client configuration to this process only.
        $changes = @{
            DATABASE_URL = ''; FOLIORA_INTEGRATION_LOCAL_OBJECT_DIR = $null; FOLIORA_SYNC_EPHEMERAL = $null
            FOLIORA_S3_REGION = 'us-east-1'; FOLIORA_S3_ALLOW_HTTP = '1'
            FOLIORA_S3_ACCESS_KEY_ID = 'foliora-local-test'; FOLIORA_S3_SECRET_ACCESS_KEY = 'foliora-local-test-secret-only'
            MINIO_ROOT_USER = 'foliora-local-test'; MINIO_ROOT_PASSWORD = 'foliora-local-test-secret-only'
            MINIO_BROWSER = 'off'; MINIO_UPDATE = 'off'; MC_DISABLE_UPDATE_CHECK = '1'
            PGHOST = '127.0.0.1'; PGUSER = 'foliora_test'; PGCONNECT_TIMEOUT = '2'; PGTZ = 'UTC'
            PGDATESTYLE = 'ISO, YMD'; PGCLIENTENCODING = 'UTF8'; PGPASSFILE = "$RunDir/no-pgpass"
            PGSERVICEFILE = "$RunDir/no-pgservice"; PGSYSCONFDIR = $RunDir
            CARGO_NET_OFFLINE = 'true'; CARGO_TARGET_DIR = $target; CARGO_BUILD_TARGET = $null
            RUSTUP_AUTO_INSTALL = '0'
            TEMP = "$RunDir/native-temp"; TMP = "$RunDir/native-temp"
            RUST_BACKTRACE = '1'; NO_PROXY = '127.0.0.1,localhost'; HTTP_PROXY = $null; HTTPS_PROXY = $null; ALL_PROXY = $null
            AWS_EC2_METADATA_DISABLED = 'true'; AWS_CONFIG_FILE = "$RunDir/no-aws-config"
            AWS_SHARED_CREDENTIALS_FILE = "$RunDir/no-aws-credentials"; MC_HOST_drill = ''
            FOLIORA_BACKUP_FIXTURE_PATH = "$RunDir/fixture.json"; FOLIORA_S3_BUCKET = 'foliora-live'
            FOLIORA_S3_ENDPOINT = ''; FOLIORA_SYNC_BIND = ''; PGPORT = ''
            FOLIORA_SYNC_BOOTSTRAP_TOKEN = 'foliora-local-test-bootstrap-token-at-least-32-bytes'
            FOLIORA_SYNC_GC_INTERVAL_SECONDS = '86400'; FOLIORA_SYNC_PAIRING_CLEANUP_SECONDS = '86400'
        }
        foreach ($item in Get-ChildItem Env:) {
            if ($item.Name -match '^(FOLIORA_|MINIO_|MC_|AWS_|PG)' -and -not $changes.ContainsKey($item.Name)) { $changes[$item.Name] = $null }
        }
        foreach ($name in $changes.Keys) {
            $EnvironmentBefore[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
            [Environment]::SetEnvironmentVariable($name, $changes[$name], 'Process')
        }
        $ports = Get-DrillPorts
        $env:PGPORT = [string]$ports[0]
        $env:FOLIORA_S3_ENDPOINT = "http://127.0.0.1:$($ports[1])"
        $env:FOLIORA_SYNC_BIND = "127.0.0.1:$($ports[3])"
        $env:MC_HOST_drill = "http://$($env:MINIO_ROOT_USER):$($env:MINIO_ROOT_PASSWORD)@127.0.0.1:$($ports[1])"
        $env:DATABASE_URL = "postgresql://foliora_test@127.0.0.1:$env:PGPORT/foliora_live"
        $script:MinioPorts = $ports[1..2]
        $script:ApiPort = $ports[3]
        $script:Service = "$target/debug/foliora-sync-service.exe"
    }
    Invoke-DrillStep 'postgres' {
        $null = Invoke-DrillNative 'initdb' "$PostgresBin/initdb.exe" @('-D', "$RunDir/pg-data", '-U', 'foliora_test', '--auth=trust', '--encoding=UTF8', '--locale=C')
        $script:Pg = Start-DrillProcess 'postgres' "$PostgresBin/postgres.exe" @('-D', "$RunDir/pg-data",
            '-h', '127.0.0.1', '-p', $env:PGPORT, '-c', 'listen_addresses=127.0.0.1')
        Wait-DrillHealth 'postgres' {
            try { $null = Invoke-DrillNative 'pg-ready' "$PostgresBin/pg_isready.exe" @('-h', '127.0.0.1', '-p', $env:PGPORT, '-U', 'foliora_test', '-d', 'postgres', '-t', '2') 5; $true }
            catch { $false }
        } $Pg -Port ([int]$env:PGPORT)
        $null = Invoke-DrillNative 'create-live' "$PostgresBin/createdb.exe" @('-w', '--template=template0', 'foliora_live')
    }
    Invoke-DrillStep 'minio' {
        $script:Minio = Start-DrillProcess 'minio' $MinioBinary @('server', "$RunDir/minio-data", '--address', "127.0.0.1:$($MinioPorts[0])",
            '--console-address', "127.0.0.1:$($MinioPorts[1])", '--certs-dir', "$RunDir/minio-certs", '--quiet')
        Wait-DrillHealth 'minio' { Test-DrillHttp "$env:FOLIORA_S3_ENDPOINT/minio/health/ready" } $Minio -Port $MinioPorts[0]
        $null = Invoke-DrillMc 'bucket-live' @('mb', 'drill/foliora-live')
    }
    Invoke-DrillStep 'restart' { Invoke-DrillTest 'restart' 'durable_repository' 'encrypted_object_and_manifest_survive_repository_restart' }
    Invoke-DrillStep 'quota' { Invoke-DrillTest 'quota' 'durable_repository' 'durable_quota_boundaries_are_atomic' }
    Invoke-DrillStep 'migration' { Invoke-DrillTest 'migration' 'migration_authorization' 'legacy_root_migration_never_promotes_a_surviving_credential' }
    Invoke-DrillStep 'seed' { Invoke-DrillTest 'seed' 'durable_repository' 'seed_backup_restore_fixture' }
    Invoke-DrillStep 'build' { $null = Invoke-DrillNative 'build' $Cargo @('build', '--locked', '--offline', '-p', 'foliora-sync-service', '--bin', 'foliora-sync-service') 1800 }
    Invoke-DrillStep 'inventory-live' { Write-DrillInventory 'live' 'foliora_live' 'foliora-live' "$RunDir/object-backup" }
    Invoke-DrillStep 'backup' {
        $null = Invoke-DrillNative 'pg-dump' "$PostgresBin/pg_dump.exe" @('-w', '-d', 'foliora_live', '--format=custom', '--file', "$RunDir/database.pgdump")
        if ((Get-Item -LiteralPath "$RunDir/database.pgdump").Length -eq 0) { throw 'Empty database backup' }
    }
    Invoke-DrillStep 'restore' {
        $null = Invoke-DrillNative 'create-restored' "$PostgresBin/createdb.exe" @('-w', '--template=template0', 'foliora_restored')
        $null = Invoke-DrillNative 'pg-restore' "$PostgresBin/pg_restore.exe" @('-w', '-d', 'foliora_restored', '--exit-on-error', "$RunDir/database.pgdump")
        $null = Invoke-DrillMc 'bucket-restored' @('mb', 'drill/foliora-restored')
        $null = Invoke-DrillMc 'restore-objects' @('mirror', "$RunDir/object-backup", 'drill/foliora-restored')
        $env:DATABASE_URL = "postgresql://foliora_test@127.0.0.1:$env:PGPORT/foliora_restored"
        $env:FOLIORA_S3_BUCKET = 'foliora-restored'
    }
    Invoke-DrillStep 'fixture-restored' { Invoke-DrillTest 'fixture-restored' 'durable_repository' 'verify_backup_restore_fixture' }
    Invoke-DrillStep 'inventory-restored' { Write-DrillInventory 'restored' 'foliora_restored' 'foliora-restored' "$RunDir/object-restored" }
    Invoke-DrillStep 'inventory-diff' {
        foreach ($kind in @('integrity', 'database', 'listing', 'objects')) {
            $extension = if ($kind -eq 'integrity') { 'jsonl' } else { 'txt' }
            Assert-DrillEqual "$RunDir/$kind-live.$extension" "$RunDir/$kind-restored.$extension"
        }
    }
    Invoke-DrillStep 'api-ready' {
        # Real HTTP service; verification requests are GET-only. Offline scrub above starts no writers.
        $script:Api = Start-DrillProcess 'api' $Service
        Wait-DrillHealth 'api' { Test-DrillHttp "http://$env:FOLIORA_SYNC_BIND/readyz" } $Api -Port $ApiPort
    }
} catch { $failed = $true }
finally {
    foreach ($cleanup in @('stop-service', 'stop-postgres', 'stop-minio', 'stop-children', 'restore-environment')) {
        try {
            Invoke-DrillStep $cleanup {
                switch ($cleanup) {
                    'stop-service' { Stop-DrillProcess $Api }
                    'stop-postgres' {
                        if ($null -ne $Pg -and -not $Pg.HasExited) {
                            try { $null = Invoke-DrillNative 'pg-stop' "$PostgresBin/pg_ctl.exe" @('stop', '-D', "$RunDir/pg-data", '-m', 'fast', '-w', '-t', '15') 20 }
                            finally { Stop-DrillProcess $Pg }
                        }
                    }
                    'stop-minio' { Stop-DrillProcess $Minio }
                    'stop-children' {
                        $stopFailed = $false
                        foreach ($child in $OwnedProcesses) {
                            try { try { Stop-DrillProcess $child } finally { $child.Dispose() } }
                            catch { $stopFailed = $true }
                        }
                        if ($stopFailed) { throw 'An owned child process could not be stopped' }
                    }
                    'restore-environment' {
                        foreach ($name in $EnvironmentBefore.Keys) { [Environment]::SetEnvironmentVariable($name, $EnvironmentBefore[$name], 'Process') }
                    }
                }
            }
        } catch { $failed = $true }
    }
    Write-DrillReport $(if ($failed) { 'FAIL' } else { 'PASS' })
    Write-Host "Report and retained synthetic artifacts: $RunDir/report.txt"
}
if ($failed) { throw "S3 drill failed; inspect retained evidence at $RunDir" }
