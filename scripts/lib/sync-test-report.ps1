# Reports are checkpoints in a newly created run directory, never success markers
# written before cleanup. Interrupted hosts leave RUNNING rather than a false PASS.
function Write-DrillReport([ValidateSet('RUNNING', 'PASS', 'FAIL')][string]$State = 'RUNNING') {
    if ($State -eq 'PASS' -and ($script:Results.Count -eq 0 -or $script:FailureReasons.Count -ne 0 -or
        @($script:Results.Values | Where-Object { $_ -ne 'PASS' }).Count -ne 0)) {
        throw 'Cannot report PASS while drill stages are incomplete or failed'
    }
    $report = @('Foliora native Windows S3 drill', "RESULT: $State")
    foreach ($status in @('RUNNING', 'PASS', 'FAIL', 'SKIP')) {
        $report += "$status`: $(@($script:Results.Values | Where-Object { $_ -eq $status }).Count)"
    }
    $report += @($script:Results.GetEnumerator() | ForEach-Object { "$($_.Value) $($_.Key)" })
    $report += @($script:FailureReasons.GetEnumerator() | ForEach-Object { "DETAIL $($_.Key): $($_.Value)" })
    $temporary = Join-Path $script:RunDir ('.report-' + [guid]::NewGuid().ToString('N') + '.tmp')
    [System.IO.File]::WriteAllLines($temporary, $report, [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::Move($temporary, (Join-Path $script:RunDir 'report.txt'), $true)
}
