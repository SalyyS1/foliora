#requires -Version 7.4.1
<#
.SYNOPSIS
Windows-only local regressions for the S3 drill harness, not an S3 integration test.
.DESCRIPTION
Uses installed Node.js and PowerShell. No PostgreSQL, S3, downloads or deletions.
Retains small synthetic logs in .test-build; stops only fixture-owned processes.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'These process-ownership regressions require Windows' }
. "$PSScriptRoot/lib/sync-test-helpers.ps1"
$Repo = Split-Path $PSScriptRoot -Parent
$BuildRoot = Join-Path $Repo '.test-build'
if (Test-Path -LiteralPath $BuildRoot) {
    if (-not (Test-Path -LiteralPath $BuildRoot -PathType Container)) {
        throw 'The .test-build path exists but is not a directory'
    }
} else {
    $null = New-Item -ItemType Directory -Path $BuildRoot
}
$RunDir = Join-Path $BuildRoot ('tooling-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $RunDir
$null = New-Item -ItemType Directory -Path "$RunDir/logs"
$OwnedProcesses = [System.Collections.Generic.List[object]]::new()
$Results = [ordered]@{ first = 'SKIP'; second = 'SKIP' }
$FailureReasons = [ordered]@{}
$Node = Resolve-DrillExecutable 'node.exe'
$Passed = 0

function Assert-Tooling([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Test-Tooling([string]$Name, [scriptblock]$Action) {
    & $Action
    $script:Passed++
    Write-Host "PASS tooling: $Name"
}
function Assert-ToolingThrows([scriptblock]$Action, [string]$Pattern) {
    try { & $Action } catch {
        if ($_.Exception.Message -notmatch $Pattern) { throw }
        return
    }
    throw "Expected a failure matching $Pattern"
}

try {
    Test-Tooling 'application lookup resolves one PATH-preferred executable' {
        $preferred = Get-Command node.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1
        Assert-Tooling ($Node -is [string] -and $Node -ceq $preferred.Source) 'Application lookup joined multiple paths'
        Assert-Tooling (Test-Path -LiteralPath $Node -PathType Leaf) 'Resolved executable is missing'
    }
    Test-Tooling 'checkpoint starts RUNNING and rejects premature PASS' {
        Write-DrillReport
        Assert-Tooling ((Get-Content "$RunDir/report.txt" -Raw).Contains('RESULT: RUNNING')) 'Missing initial checkpoint'
        Assert-ToolingThrows { Write-DrillReport 'PASS' } 'incomplete or failed'
    }
    Test-Tooling 'stages checkpoint active state before executing work' {
        Invoke-DrillStep 'first' {
            $text = Get-Content "$RunDir/report.txt" -Raw
            Assert-Tooling ($text.Contains('RUNNING first')) 'Active stage was not persisted before work'
        }
        Assert-Tooling ($Results.first -eq 'PASS') 'Completed stage missing'
    }
    Test-Tooling 'failure checkpoints survive and preserve the error' {
        Assert-ToolingThrows { Invoke-DrillStep 'second' { throw 'synthetic failure' } } '^synthetic failure$'
        $text = Get-Content "$RunDir/report.txt" -Raw
        Assert-Tooling ($text.Contains('FAIL second') -and $text.Contains('synthetic failure')) 'Failure checkpoint missing'
        Assert-ToolingThrows { Write-DrillReport 'PASS' } 'incomplete or failed'
        Write-DrillReport 'FAIL'
    }
    Test-Tooling 'completed stages can produce a final PASS' {
        $savedResults = $script:Results
        $savedFailures = $script:FailureReasons
        $savedRunDir = $script:RunDir
        $probeRunDir = Join-Path $RunDir 'pass-probe'
        $null = New-Item -ItemType Directory -Path $probeRunDir
        try {
            $script:Results = [ordered]@{ first = 'PASS'; second = 'PASS' }
            $script:FailureReasons = [ordered]@{}
            $script:RunDir = $probeRunDir
            Write-DrillReport 'PASS'
            Assert-Tooling ((Get-Content "$probeRunDir/report.txt" -Raw).Contains('RESULT: PASS')) 'Final PASS missing'
        } finally {
            $script:RunDir = $savedRunDir
            $script:Results = $savedResults
            $script:FailureReasons = $savedFailures
            Write-DrillReport
        }
    }
    Test-Tooling 'native argv round-trip includes empty, quotes, Unicode and trailing slashes' {
        $expected = @('', 'two words', 'Tiếng Việt', 'quote"inside', 'C:\path with spaces\', 'slashes\\"quote')
        $log = Invoke-DrillNative 'argv' $Node (@('-e', 'process.stdout.write(JSON.stringify(process.argv.slice(1)))', '--') + $expected) 10
        $actual = @(Get-Content -LiteralPath $log -Raw | ConvertFrom-Json)
        Assert-Tooling ($actual.Count -eq $expected.Count) 'Argument count changed'
        for ($i = 0; $i -lt $expected.Count; $i++) {
            Assert-Tooling ($actual[$i] -ceq $expected[$i]) "Argument $i changed"
        }
    }
    Test-Tooling 'nonzero native exits cannot pass' {
        Assert-ToolingThrows { Invoke-DrillNative 'exit-seven' $Node @('-e', 'process.exit(7)') 10 } 'exited with code 7'
    }
    Test-Tooling 'deadline stops the owned process' {
        Assert-ToolingThrows { Invoke-DrillNative 'timeout' $Node @('-e', 'setTimeout(()=>{},30000)') 1 } 'exceeded its deadline'
        Assert-Tooling $OwnedProcesses[$OwnedProcesses.Count - 1].HasExited 'Timed-out process remained alive'
    }
    Test-Tooling 'cleanup owns descendants even after their parent exits' {
        $spawn = 'const {spawn}=require("node:child_process");const c=spawn(process.execPath,["-e","setTimeout(()=>{},30000)"],{detached:true,stdio:"ignore"});process.stdout.write(String(c.pid));c.unref();'
        $parent = Start-DrillProcess 'orphan-parent' $Node @('-e', $spawn)
        Assert-Tooling ($parent.WaitForExit(10000)) 'Fixture parent did not exit'
        $childId = [int](Get-Content "$RunDir/logs/orphan-parent.stdout.log" -Raw)
        $child = [System.Diagnostics.Process]::GetProcessById($childId)
        try {
            $null = $child.Handle # Retain identity independently of PID reuse.
            Assert-Tooling (-not $child.HasExited) 'Fixture descendant was not alive before cleanup'
            Stop-DrillProcess $parent
            Assert-Tooling ($child.WaitForExit(5000)) 'Cleanup returned with a live descendant'
            Stop-DrillProcess $parent # Repeated cleanup must be harmless.
        } finally {
            # This handle was captured for a child created by this fixture only.
            if (-not $child.HasExited) { $child.Kill($true); $null = $child.WaitForExit(5000) }
            $child.Dispose()
        }
    }
    Test-Tooling 'inventory comparison rejects same-length corruption' {
        Write-DrillLines "$RunDir/before.txt" @('b', 'a')
        Write-DrillLines "$RunDir/after.txt" @('a', 'b')
        Assert-DrillEqual "$RunDir/before.txt" "$RunDir/after.txt"
        Write-DrillLines "$RunDir/after.txt" @('a', 'c')
        Assert-ToolingThrows { Assert-DrillEqual "$RunDir/before.txt" "$RunDir/after.txt" } 'inventories differ'
    }
    Test-Tooling 'stopping one job leaves another fixture job running' {
        $first = Start-DrillProcess 'isolated-first' $Node @('-e', 'setTimeout(()=>{},30000)')
        $second = Start-DrillProcess 'isolated-second' $Node @('-e', 'setTimeout(()=>{},30000)')
        Stop-DrillProcess $first
        Assert-Tooling $first.HasExited 'Stopped job root remained alive'
        Assert-Tooling (-not $second.HasExited) 'Stopping one job affected another job'
        Stop-DrillProcess $second
    }
    Test-Tooling 'closing the last job handle kills surviving descendants' {
        $spawn = 'const {spawn}=require("node:child_process");const c=spawn(process.execPath,["-e","setTimeout(()=>{},30000)"],{detached:true,stdio:"ignore"});process.stdout.write(String(c.pid));c.unref();'
        $owner = [Foliora.Drill.OwnedProcess]::Start($Node, @('-e', $spawn), $Repo,
            "$RunDir/logs/close-parent.stdout.log", "$RunDir/logs/close-parent.stderr.log")
        $closed = $false; $child = $null
        try {
            Assert-Tooling ($owner.WaitForExit(10000)) 'Fixture parent did not exit'
            $childId = [int](Get-Content "$RunDir/logs/close-parent.stdout.log" -Raw)
            $child = [System.Diagnostics.Process]::GetProcessById($childId)
            $null = $child.Handle
            Assert-Tooling (-not $child.HasExited) 'Fixture child was not alive before close'
            $owner.Dispose(); $closed = $true
            Assert-Tooling ($child.WaitForExit(5000)) 'Job close left a live descendant'
            $owner.Dispose()
        } finally {
            if (-not $closed) { try { $owner.Stop(10000) } finally { $owner.Dispose() } }
            if ($null -ne $child) {
                if (-not $child.HasExited) { $child.Kill($true); $null = $child.WaitForExit(5000) }
                $child.Dispose()
            }
        }
    }
    # Individual regression cases are reported through the process exit and
    # console count. Collapse the checkpoint to one aggregate stage only after
    # every case has passed, so the retained report cannot expose a stale
    # synthetic failure from the checkpoint regression itself.
    $script:Results = [ordered]@{ tooling = 'PASS' }
    $script:FailureReasons = [ordered]@{}
} catch {
    $FailureReasons['tooling'] = $_.Exception.Message
    try { Write-DrillReport 'FAIL' } catch { Write-Warning 'Could not checkpoint tooling failure' }
    throw
} finally {
    $cleanupFailed = $false
    foreach ($process in $OwnedProcesses) {
        try { try { Stop-DrillProcess $process } finally { $process.Dispose() } }
        catch { $cleanupFailed = $true }
    }
    if ($cleanupFailed) {
        $FailureReasons['cleanup'] = 'Fixture cleanup failed'
        try { Write-DrillReport 'FAIL' } catch { Write-Warning 'Could not checkpoint cleanup failure' }
        throw 'Fixture cleanup failed'
    }
}

# The retained PASS is written only after every fixture-owned process has been
# stopped and its handles disposed. An interrupted host before this point leaves
# the report RUNNING rather than claiming a complete tooling run.
try {
    Write-DrillReport 'PASS'
    Write-Host "Tooling regressions: $Passed passed; evidence: $RunDir"
} catch {
    $FailureReasons['final-report'] = $_.Exception.Message
    try { Write-DrillReport 'FAIL' } catch { Write-Warning 'Could not checkpoint final-report failure' }
    throw
}
