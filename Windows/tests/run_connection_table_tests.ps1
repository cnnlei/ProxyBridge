[CmdletBinding()]
param(
    [ValidateRange(1, 10000)]
    [int]$Repeat = 1,

    [switch]$SkipBuild,

    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$gcc = 'E:\progi\mingw64\bin\gcc.exe'
$sourceRoot = Split-Path -Parent $PSScriptRoot
$moduleSource = Join-Path $sourceRoot 'src\connection_table.c'
$testSource = Join-Path $PSScriptRoot 'connection_table_tests.c'
$outputDirectory = Join-Path $PSScriptRoot 'output'
$testExecutable = Join-Path $outputDirectory 'connection_table_tests_gcc.exe'

function Format-Command {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$ArgumentList
    )

    $quotedArguments = foreach ($argument in $ArgumentList) {
        '"' + $argument.Replace('"', '\"') + '"'
    }

    return '"' + $FilePath + '" ' + ($quotedArguments -join ' ')
}

if (-not (Test-Path -LiteralPath $gcc -PathType Leaf)) {
    throw "Required GCC was not found: $gcc"
}

if (-not $SkipBuild) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null

    $compilerArguments = @(
        '-m64',
        '-std=c11',
        '-O2',
        '-Wall',
        '-Wextra',
        '-Wpedantic',
        '-Werror',
        '-D_WIN32_WINNT=0x0601',
        $moduleSource,
        $testSource,
        '-o',
        $testExecutable
    )

    Write-Output ('BUILD_COMMAND: ' + (Format-Command -FilePath $gcc -ArgumentList $compilerArguments))
    $compilerOutput = & $gcc @compilerArguments 2>&1
    $compilerExitCode = $LASTEXITCODE
    if ($compilerOutput) {
        $compilerOutput | ForEach-Object { Write-Output $_ }
    }
    Write-Output "BUILD_EXIT_CODE: $compilerExitCode"
    if ($compilerExitCode -ne 0) {
        exit $compilerExitCode
    }
}

if (-not (Test-Path -LiteralPath $testExecutable -PathType Leaf)) {
    throw "Test executable was not found: $testExecutable"
}

$testArguments = @()
if ($Quiet) {
    $testArguments += '--quiet'
}

Write-Output ('TEST_COMMAND: ' + (Format-Command -FilePath $testExecutable -ArgumentList $testArguments))

for ($run = 1; $run -le $Repeat; $run++) {
    $testOutput = & $testExecutable @testArguments 2>&1
    $testExitCode = $LASTEXITCODE

    if (-not $Quiet -or $testExitCode -ne 0) {
        $testOutput | ForEach-Object { Write-Output $_ }
    }

    Write-Output "RUN $run/$Repeat EXIT_CODE: $testExitCode"
    if ($testExitCode -ne 0) {
        exit $testExitCode
    }
}

Write-Output "ALL_RUNS_PASSED: $Repeat"
exit 0
