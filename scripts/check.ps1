[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$commands = @(
    @("cargo", "check", "--workspace"),
    @("cargo", "fmt", "--all", "--", "--check"),
    @("cargo", "clippy", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"),
    @("cargo", "test", "--workspace"),
    @("cargo", "build", "--workspace", "--release"),
    @("cargo", "tree", "--workspace"),
    @("cargo", "tree", "--duplicates"),
    @("cargo", "metadata", "--no-deps")
)

foreach ($command in $commands) {
    Write-Host ("> " + ($command -join " "))
    & $command[0] $command[1..($command.Length - 1)]
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $($command -join ' ')"
    }
}
