param(
    [ValidateRange(1, 65535)]
    [int]$Port = 39001,

    [ValidateRange(3, 120)]
    [int]$DurationSeconds = 12,

    [ValidateRange(0, 30)]
    [int]$CountdownSeconds = 0,

    [ValidateRange(65536, 1048576)]
    [int]$ChunkBytes = 1048576,

    [ValidateRange(10, 1000)]
    [int]$DelayMilliseconds = 10
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$repoRoot = Split-Path -Parent $PSScriptRoot
$fixture = Join-Path $repoRoot 'target\release\procnet-fixture.exe'
$server = $null
$client = $null
$stream = $null

function Show-ServerResult {
    $output = $server.StandardOutput.ReadToEnd()
    $errors = $server.StandardError.ReadToEnd()
    if ($output) {
        Write-Host $output.TrimEnd()
    }
    if ($errors) {
        Write-Host $errors.TrimEnd() -ForegroundColor Red
    }
}

try {
    if (-not (Test-Path -LiteralPath $fixture -PathType Leaf)) {
        throw "Fixture not found: $fixture`nRun: cargo build -p procnet-fixture --release"
    }

    $existingListener = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
    if ($existingListener) {
        throw "TCP port $Port is already in use. Close the existing server or run this script with -Port <another-port>."
    }

    Write-Host ''
    Write-Host 'ProcNet high-risk notification demo' -ForegroundColor Cyan
    Write-Host 'Before the countdown ends:'
    Write-Host '  1. Keep ProcNet GUI open and showing: 正在采集'
    Write-Host '  2. Keep the default thresholds, or use 1048576 B/s for an easier demo'
    Write-Host '  3. Switch back to the ProcNet overview for the recording'
    Write-Host ''

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $fixture
    $startInfo.Arguments = "tcp-server --bind 127.0.0.1:$Port"
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $server = [System.Diagnostics.Process]::new()
    $server.StartInfo = $startInfo
    if (-not $server.Start()) {
        throw 'Fixture server process could not be started.'
    }
    $readyLine = $server.StandardOutput.ReadLine()
    if (-not $readyLine -or $readyLine -notmatch 'FIXTURE_TCP_SERVER_READY') {
        $errors = $server.StandardError.ReadToEnd()
        throw "Fixture server did not become ready. $errors"
    }
    Write-Host $readyLine

    for ($remaining = $CountdownSeconds; $remaining -gt 0; $remaining--) {
        Write-Host "Traffic starts in $remaining second(s)..."
        Start-Sleep -Seconds 1
    }

    $client = [System.Net.Sockets.TcpClient]::new()
    $client.NoDelay = $true
    $client.Connect('127.0.0.1', $Port)
    $stream = $client.GetStream()
    $buffer = [byte[]]::new($ChunkBytes)
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    [uint64]$transferred = 0

    Write-Host "Generating controlled bidirectional traffic for $DurationSeconds seconds..." -ForegroundColor Yellow
    while ($timer.Elapsed.TotalSeconds -lt $DurationSeconds) {
        $stream.Write($buffer, 0, $buffer.Length)
        $received = 0
        while ($received -lt $buffer.Length) {
            $count = $stream.Read($buffer, $received, $buffer.Length - $received)
            if ($count -le 0) {
                throw 'Fixture connection closed unexpectedly.'
            }
            $received += $count
        }
        $transferred += [uint64]$buffer.Length
        Start-Sleep -Milliseconds $DelayMilliseconds
    }

    $stream.Dispose()
    $stream = $null
    $client.Dispose()
    $client = $null

    if (-not $server.WaitForExit(5000)) {
        throw 'Fixture server did not exit within 5 seconds after the client disconnected.'
    }
    Show-ServerResult
    $elapsedSeconds = [Math]::Max($timer.Elapsed.TotalSeconds, 0.001)
    $mib = [Math]::Round($transferred / 1MB, 1)
    $averageMibPerSecond = [Math]::Round(($transferred / 1MB) / $elapsedSeconds, 1)
    Write-Host ''
    Write-Host "Completed: approximately $mib MiB uploaded and echoed back." -ForegroundColor Green
    Write-Host "Average rate per direction: approximately $averageMibPerSecond MiB/s." -ForegroundColor Green
    Write-Host 'Expected GUI result: a high-risk popup and an automatic incident session.' -ForegroundColor Green
}
catch {
    Write-Host ''
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
finally {
    if ($stream) {
        $stream.Dispose()
    }
    if ($client) {
        $client.Dispose()
    }
    if ($server) {
        $server.Refresh()
        if (-not $server.HasExited) {
            Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
            $server.WaitForExit(3000) | Out-Null
        }
        $server.Dispose()
    }
}
