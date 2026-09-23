# Helpers are dot-sourced by test-sync-s3.ps1; all paths/processes belong to that run.
. "$PSScriptRoot/sync-test-report.ps1"

function Resolve-DrillExecutable([string]$Name) {
    # Multiple installations can be returned for an explicit .exe lookup. Match
    # PATH precedence, never stringify an array of paths into one invalid filename.
    return (Get-Command $Name -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
}

function Invoke-DrillStep([string]$Name, [scriptblock]$Action) {
    try {
        $script:Results[$Name] = 'RUNNING'
        Write-DrillReport
        & $Action | Out-Null
        $script:Results[$Name] = 'PASS'
        Write-DrillReport
        Write-Host "PASS $Name"
    } catch {
        $script:Results[$Name] = 'FAIL'
        # Native output stays in logs; messages here contain stage names/codes, never environment dumps.
        $script:FailureReasons[$Name] = $_.Exception.Message
        $originalError = $_
        try { Write-DrillReport } catch { Write-Warning 'Could not checkpoint the failed drill stage' }
        Write-Host "FAIL $Name (see retained logs)"
        throw $originalError
    }
}

function Start-DrillProcess([string]$Name, [string]$File, [string[]]$Arguments = @()) {
    if (-not ('Foliora.Drill.OwnedProcess' -as [type])) {
        Add-Type -Path @("$PSScriptRoot/owned-drill-process-native.cs", "$PSScriptRoot/owned-drill-process.cs")
    }
    # The launcher assigns a suspended process to a non-inherited kill-on-close
    # job before resuming it. Descendants remain owned after the parent exits.
    $process = [Foliora.Drill.OwnedProcess]::Start($File, $Arguments, $script:Repo,
        "$script:RunDir/logs/$Name.stdout.log", "$script:RunDir/logs/$Name.stderr.log")
    $script:OwnedProcesses.Add($process)
    return $process
}

function Invoke-DrillNative([string]$Name, [string]$File, [string[]]$Arguments, [int]$Seconds = 180) {
    $process = Start-DrillProcess $Name $File $Arguments
    # Bound the captured process itself; never wait implicitly for a descendant tree.
    if (-not $process.WaitForExit($Seconds * 1000)) {
        Stop-DrillProcess $process
        throw "$Name exceeded its deadline"
    }
    # Start-Process does not populate LASTEXITCODE; take it from the owned process explicitly.
    $LASTEXITCODE = $process.ExitCode
    if ($LASTEXITCODE -ne 0) { throw "$Name exited with code $LASTEXITCODE" }
    return "$script:RunDir/logs/$Name.stdout.log"
}

function Stop-DrillProcess([object]$Process) {
    if ($null -eq $Process) { return }
    # Never skip an exited root: Stop verifies that the entire owned job is empty.
    $Process.Stop(10000)
}

function Wait-DrillHealth([string]$Name, [scriptblock]$Probe,
    [object]$Process, [Parameter(Mandatory)][ValidateRange(1, 65535)][int]$Port,
    [int]$Seconds = 60) {
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    while ($timer.Elapsed.TotalSeconds -lt $Seconds) {
        if ($Process.HasExited) { throw "$Name process exited before readiness" }
        try {
            $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction Stop)
        } catch {
            # No listener yet is retryable. Missing cmdlet, access denial, or CIM failure is fatal.
            if ($_.FullyQualifiedErrorId -notlike 'CmdletizationQuery_NotFound*') {
                throw "$Name listener ownership query failed; refusing to probe"
            }
            $listeners = @()
        }
        if ($listeners.Count) {
            foreach ($listener in $listeners) {
                if ($listener.OwningProcess -ne $Process.Id -or $listener.LocalAddress -ne '127.0.0.1') {
                    throw "$Name port has an unexpected listener; refusing to probe"
                }
            }
            if ($Process.HasExited) { throw "$Name process exited before health probe" }
            if (& $Probe) {
                if ($Process.HasExited) { throw "$Name process exited during health probe" }
                return
            }
        }
        Start-Sleep -Milliseconds 250
    }
    throw "$Name readiness deadline exceeded"
}

function Test-DrillHttp([string]$Uri) {
    try {
        $response = Invoke-WebRequest -Uri $Uri -NoProxy -TimeoutSec 2 -MaximumRedirection 0 -SkipHttpErrorCheck
        return $response.StatusCode -eq 200
    } catch { return $false }
}

function Get-DrillPorts {
    $listeners = [System.Collections.Generic.List[System.Net.Sockets.TcpListener]]::new()
    try {
        # Reserve all four simultaneously so this run cannot pick the same port twice.
        foreach ($index in 1..4) {
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
            $listeners.Add($listener)
            $listener.Start()
        }
        return @($listeners | ForEach-Object { $_.LocalEndpoint.Port })
    } finally { foreach ($listener in $listeners) { $listener.Stop() } }
}

function Invoke-DrillTest([string]$Name, [string]$Target, [string]$Test) {
    $log = Invoke-DrillNative $Name $script:Cargo @('test', '--locked', '--offline', '-p',
        'foliora-sync-service', '--test', $Target, $Test, '--', '--ignored', '--exact', '--nocapture') 1800
    # Cargo can return success when an exact filter matches zero tests.
    if (-not (Select-String -LiteralPath $log -Pattern 'test result: ok\. 1 passed; 0 failed;' -Quiet)) {
        throw "$Name did not execute exactly one successful test"
    }
}

function Invoke-DrillMc([string]$Name, [string[]]$Arguments) {
    return Invoke-DrillNative $Name $script:McBinary (@('--config-dir', "$script:RunDir/mc", '--json', '--no-color') + $Arguments)
}

function Write-DrillLines([string]$Path, [string[]]$Lines) {
    [Array]::Sort($Lines, [StringComparer]::Ordinal)
    [System.IO.File]::WriteAllLines($Path, $Lines, [System.Text.UTF8Encoding]::new($false))
}

function Assert-DrillEqual([string]$Before, [string]$After) {
    if ((Get-FileHash -LiteralPath $Before -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $After -Algorithm SHA256).Hash) {
        throw 'Independent inventories differ; inspect retained before/after files'
    }
}

function Write-DrillInventory([string]$Label, [string]$Database, [string]$Bucket, [string]$ObjectDir) {
    $integrity = Invoke-DrillNative "integrity-$Label" $script:Service @('--verify-integrity', '--inventory-jsonl')
    $lines = @(Get-Content -LiteralPath $integrity)
    if (-not $lines.Count) { throw 'Integrity inventory is unexpectedly empty' }
    Write-DrillLines "$script:RunDir/integrity-$Label.jsonl" $lines
    # Independently enumerate every public table, including SQLx migration bookkeeping.
    $tableLog = Invoke-DrillNative "tables-$Label" "$script:PostgresBin/psql.exe" @('-X', '-w', '-d', $Database,
        '-At', '-v', 'ON_ERROR_STOP=1', '-c', "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename")
    $tables = @(Get-Content -LiteralPath $tableLog)
    if (-not $tables.Count) { throw 'Database inventory is unexpectedly empty' }
    $rows = @(); $index = 0
    foreach ($table in $tables) {
        if ($table -notmatch '^[a-z_][a-z0-9_]*$') { throw 'Unexpected synthetic table identifier' }
        $sql = "SELECT row_to_json(t)::text FROM public.`"$table`" t"
        $rowLog = Invoke-DrillNative "rows-$Label-$index" "$script:PostgresBin/psql.exe" @('-X', '-w', '-d', $Database,
            '-At', '-v', 'ON_ERROR_STOP=1', '-c', $sql)
        $rows += "TABLE|$table"
        $rows += @(Get-Content -LiteralPath $rowLog | ForEach-Object { "$table|$_" })
        $index++
    }
    Write-DrillLines "$script:RunDir/database-$Label.txt" $rows
    $listing = Invoke-DrillMc "listing-$Label" @('ls', '--recursive', "drill/$Bucket")
    $objects = @(Get-Content -LiteralPath $listing | ForEach-Object {
        $entry = $_ | ConvertFrom-Json
        if ($entry.status -ne 'success' -or $entry.type -ne 'file') { throw 'Unexpected S3 listing entry' }
        "$($entry.key)|$($entry.size)"
    })
    if (-not $objects.Count) { throw 'S3 inventory is unexpectedly empty' }
    Write-DrillLines "$script:RunDir/listing-$Label.txt" $objects
    $null = Invoke-DrillMc "mirror-$Label" @('mirror', "drill/$Bucket", $ObjectDir)
    $hashes = @(Get-ChildItem -LiteralPath $ObjectDir -File -Recurse | ForEach-Object {
        $relative = [System.IO.Path]::GetRelativePath($ObjectDir, $_.FullName).Replace('\', '/')
        "$relative|$($_.Length)|$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash)"
    })
    if (-not $hashes.Count) { throw 'Downloaded object inventory is unexpectedly empty' }
    Write-DrillLines "$script:RunDir/objects-$Label.txt" $hashes
}
