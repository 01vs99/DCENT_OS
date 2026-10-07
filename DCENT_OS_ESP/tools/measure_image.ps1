<#
.SYNOPSIS
    DCENT_axe UI Gauntlet measurement station (Stage M) - Windows PowerShell port
    of tools/measure_image.sh.

.DESCRIPTION
    Wraps GAUNTLET_LOOP.md Stage B steps 1-4 and writes the `measure.json` that a
    blind critic is handed (CRITIC_RUBRIC.md sections 0/1/5):

      * image bytes per board + the OTA slot size + percent used  (the HARD budget)
      * the ELF text/data/bss triple
      * the invocation-aware handler count from tools/count_handlers.py
      * a per-asset byte table (dashboard.rs and the include_str! assets), so a
        lane that grows the image has to say which asset paid for it
      * host-gate pass/fail counts
      * delta_vs_baseline when a previous measure.json is supplied

    The document itself is written by tools/measure_assemble.py, which BOTH this
    script and tools/measure_image.sh call. Neither port formats JSON of its own:
    round 1 shipped two independent writers and they disagreed on the shape a
    blind critic was handed (`xtensa_check` was a list from one and a bare string
    or null from the other; the `boards` container had already been coerced to a
    string array once). tools/check_measure_ports.py runs both and diffs them.

    Builders do NOT run this: C:/bt is one shared warm ESP-IDF cache and the
    ESP-IDF path-length limit forbids per-worktree target dirs, so the lead runs
    it serially, one lane at a time (GAUNTLET_LOOP.md Stage M).

    Written for Windows PowerShell 5.1: no pipeline chain operators, no ternary,
    no null-coalescing. Native tools are launched through Start-Process so their
    exit codes are honest (5.1 wraps a redirected native stderr in ErrorRecords).

.PARAMETER Lane
    Lane id recorded in measure.json and used in the default evidence path.

.PARAMETER Pass
    Pass id used in the default evidence path (projects/.axe-gauntlet/<pass>/<lane>).

.PARAMETER Boards
    Board targets to build and measure.

.PARAMETER Out
    measure.json path. Defaults to <evidence>/measure.json.

.PARAMETER TargetDir
    CARGO_TARGET_DIR for the Xtensa build. One shared warm cache; do not fork it.

.PARAMETER HostTargetDir
    CARGO_TARGET_DIR for the host gate. Defaults outside the worktree so a
    per-worktree `target/` never accumulates (root  disk hygiene).

.PARAMETER Baseline
    A previous measure.json to diff against (fills delta_vs_baseline).

.PARAMETER SkipBuild
    Skip the Xtensa build + espflash step (handlers, assets and host gate only).

.PARAMETER SkipHostGate
    Skip the host gate.

.EXAMPLE
    .\tools\measure_image.ps1 -Lane P1-I3 -Baseline projects\.axe-gauntlet\pass1\baseline\measure.json

.NOTES
    Exit 0 = measured and every board fits its slot. Exit 1 = a board's image
    exceeds its OTA slot, the handler census failed, or a tool is missing.
    Fail-closed: an image that does not fit is a failed lane, never a warning.
#>
[CmdletBinding()]
param(
    [string]$Lane = "baseline",
    [string]$Pass = "pass1",
    [string[]]$Boards = @("bitaxe-hex-supra", "bitaxe-gamma"),
    [string]$Out = "",
    [string]$ImageDir = "",
    [string]$TargetDir = "C:/bt",
    [string]$HostTargetDir = "C:/bt-host",
    [string]$Baseline = "",
    [switch]$SkipBuild,
    [switch]$SkipHostGate,
    [switch]$AllowCr
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = (Resolve-Path (Join-Path $ScriptDir "..")).Path
$RepoRoot = (Resolve-Path (Join-Path $RootDir "../..")).Path

$Python = $env:PYTHON
if (-not $Python) { $Python = "python" }
$Cargo = $env:CARGO
if (-not $Cargo) { $Cargo = "cargo" }
$Espflash = $env:ESPFLASH
if (-not $Espflash) { $Espflash = "espflash" }
$SizeTool = $env:SIZE_TOOL
if (-not $SizeTool) { $SizeTool = "xtensa-esp32s3-elf-size" }
$HostTarget = $env:HOST_TARGET
if (-not $HostTarget) { $HostTarget = "x86_64-pc-windows-msvc" }
# rust-toolchain.toml pins `esp`, so the host gate must name a host toolchain.
$HostToolchain = $env:HOST_TOOLCHAIN
if (-not $HostToolchain) { $HostToolchain = "+stable" }

$EvidenceDir = Join-Path $RepoRoot "projects/.axe-gauntlet/$Pass/$Lane"
if (-not $Out) { $Out = Join-Path $EvidenceDir "measure.json" }
if (-not $ImageDir) { $ImageDir = Join-Path $EvidenceDir "images" }
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Out) | Out-Null
New-Item -ItemType Directory -Force -Path $ImageDir | Out-Null

$Work = Join-Path ([System.IO.Path]::GetTempPath()) ("axe-measure-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $Work | Out-Null
$GateLog = Join-Path $EvidenceDir "gate.log"

# Start-Process joins -ArgumentList with spaces and does NOT quote, so every
# argument that can contain a space (every path in this repo does) must arrive
# pre-quoted or the callee sees it split.
function ConvertTo-QuotedArg {
    param([string]$Value)
    if ($Value -eq "") { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }
    $escaped = $Value -replace '(\\*)"', '$1$1\"'
    $escaped = $escaped -replace '(\\+)$', '$1$1'
    return '"' + $escaped + '"'
}

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        # PowerShell's automatic Mandatory-parameter validation for a [string[]]
        # rejects the WHOLE array if ANY element is an empty string (not just an
        # empty array) - "Cannot bind argument to parameter 'Arguments' because
        # it is an empty string." `--baseline ""` (the default, i.e. every run
        # that does not pass -Baseline) puts exactly one empty element at the
        # tail of $assembleArgs below, so the assemble call - the one Invoke-
        # Native call this script cannot skip - threw on every default run.
        # [AllowEmptyString()] disables only that per-element emptiness check;
        # Mandatory still refuses a $null or fully-empty array.
        [Parameter(Mandatory = $true)][AllowEmptyString()][string[]]$Arguments,
        [string]$WorkingDirectory = $RootDir,
        [string]$StdoutFile = "",
        [switch]$AllowFailure,
        # Machine-readable stdout (the handler census JSON) must not have stderr
        # folded into it, or the shared assembler is handed corrupt JSON.
        [switch]$KeepStderrSeparate
    )
    $so = $StdoutFile
    if (-not $so) { $so = Join-Path $Work ("out-" + [System.Guid]::NewGuid().ToString("N") + ".txt") }
    $se = "$so.err"
    $quoted = @($Arguments | ForEach-Object { ConvertTo-QuotedArg $_ })
    $p = Start-Process -FilePath $FilePath -ArgumentList $quoted `
        -WorkingDirectory $WorkingDirectory -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput $so -RedirectStandardError $se
    if (Test-Path $se) {
        if ($KeepStderrSeparate) {
            Get-Content $se -Raw -ErrorAction SilentlyContinue | Write-Host
        } else {
            Get-Content $se -Raw -ErrorAction SilentlyContinue | Add-Content -Path $so -Encoding utf8
        }
        Remove-Item $se -Force -ErrorAction SilentlyContinue
    }
    if ($p.ExitCode -ne 0 -and -not $AllowFailure) {
        Get-Content $so -ErrorAction SilentlyContinue | Write-Host
        throw "$FilePath exited $($p.ExitCode)"
    }
    return [pscustomobject]@{ ExitCode = $p.ExitCode; Log = $so }
}

# ---------------------------------------------------------------------------
# 0. Embedded-asset CR refusal (P1-I6; lead fix at merge, blind-critic must-fix
#    1 - this port had no Step 0, so a Windows-only run bypassed the refusal
#    entirely). A SOURCE-state check: it runs unconditionally, before every
#    other step, regardless of -SkipBuild/-SkipHostGate, because a CRLF
#    checkout inflates the image whether or not this run goes on to build one.
#    Mirrors `measure_image.sh` step 0 exactly; `check_measure_ports.py`
#    asserts both ports keep it.
# ---------------------------------------------------------------------------
Write-Host "== embedded-asset CR check =="
$crArgs = @((Join-Path $ScriptDir "measure_cr_check.py"), "--dcentaxe-src", (Join-Path $RootDir "dcentaxe/src"))
if ($AllowCr) { $crArgs += "--allow-cr" }
$crCheck = Invoke-Native -FilePath $Python -Arguments $crArgs -AllowFailure
if ($crCheck.ExitCode -ne 0) {
    throw "embedded-asset CR check FAILED (exit $($crCheck.ExitCode)) - see output above"
}

# ---------------------------------------------------------------------------
# 1. Handler census (Stage B step 4) - cheap, and it is the number that gates a
#    lane's brief before a critic is spent on it.
# ---------------------------------------------------------------------------
Write-Host "== handler census =="
$handlersJson = Join-Path $Work "handlers.json"
$r = Invoke-Native -FilePath $Python -Arguments @((Join-Path $ScriptDir "count_handlers.py"), "--json") -StdoutFile $handlersJson -AllowFailure -KeepStderrSeparate
if ($r.ExitCode -ne 0) {
    Get-Content $handlersJson -ErrorAction SilentlyContinue | Write-Host
    throw "handler census FAILED - see tools/count_handlers.py output"
}
$r2 = Invoke-Native -FilePath $Python -Arguments @((Join-Path $ScriptDir "count_handlers.py"), "--quiet")
Get-Content $r2.Log | Write-Host

# ---------------------------------------------------------------------------
# 2. Host gate (Stage B step 1)
# ---------------------------------------------------------------------------
$gateRows = @()
function Invoke-Gate {
    param([string]$Label, [string[]]$CargoArgs)
    Write-Host "== host gate: $Label =="
    $log = Join-Path $Work "gate-$Label.out"
    # Short target dir outside the worktree: a per-worktree `target/` is exactly
    # the accumulation the root  disk-hygiene rule forbids.
    $env:CARGO_TARGET_DIR = $HostTargetDir
    $res = Invoke-Native -FilePath $Cargo -Arguments $CargoArgs -StdoutFile $log -AllowFailure
    Add-Content -Path $GateLog -Value (Get-Content $log -Raw) -Encoding utf8
    $passed = 0
    $failed = 0
    foreach ($line in Get-Content $log) {
        if ($line -match '^test result:') {
            if ($line -match '(\d+)\s+passed') { $passed += [int]$Matches[1] }
            if ($line -match '(\d+)\s+failed') { $failed += [int]$Matches[1] }
        }
    }
    $status = "failed"
    if ($res.ExitCode -eq 0) { $status = "ok" }
    Write-Host "$Label`: $status ($passed passed, $failed failed)"
    return [pscustomobject]@{ label = $Label; passed = $passed; failed = $failed; status = $status }
}

$GateTsv = Join-Path $Work "gate.tsv"
if (-not $SkipHostGate) {
    Set-Content -Path $GateLog -Value "" -Encoding utf8
    $gateRows += Invoke-Gate -Label "core" -CargoArgs @(
        $HostToolchain, "test", "--locked", "--target", $HostTarget,
        "-p", "dcentaxe-core", "-p", "dcentaxe-bap", "-p", "dcentaxe-stratum",
        "-p", "dcentaxe-mining", "-p", "dcentaxe-stratum-v2", "-p", "dcentaxe-asic",
        "-p", "dcentaxe-lora")
    $gateRows += Invoke-Gate -Label "hal" -CargoArgs @(
        $HostToolchain, "test", "--locked", "--target", $HostTarget,
        "-p", "dcentaxe-hal", "--no-default-features", "--features", "pins-bitaxe")
} else {
    Write-Host "== host gate SKIPPED (-SkipHostGate) =="
}
# One TSV row per suite: label, passed, failed, status. Identical to the shell
# port's gate.tsv, because measure_assemble.py reads exactly this.
$gateLines = @()
foreach ($row in $gateRows) {
    $gateLines += ("{0}`t{1}`t{2}`t{3}" -f $row.label, $row.passed, $row.failed, $row.status)
}
[System.IO.File]::WriteAllText($GateTsv, (($gateLines -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))

# ---------------------------------------------------------------------------
# 3. Per-board image measurement (Stage B steps 2-3)
# ---------------------------------------------------------------------------
function Get-OtaSlotSize {
    param([string]$Csv)
    foreach ($raw in Get-Content $Csv) {
        $line = ($raw -split "#", 2)[0].Trim()
        if (-not $line) { continue }
        $cols = ($line -split ",") | ForEach-Object { $_.Trim() }
        if ($cols.Count -ge 5 -and $cols[0] -eq "ota_0" -and $cols[1] -eq "app") {
            return [Convert]::ToInt64($cols[4].Substring(2), 16)
        }
    }
    throw "ota_0 app partition not found in $Csv"
}

# Board-result collection. This is an ARRAY of row objects, not a dictionary,
# and its name is `$boardRows` - deliberately NOT `$boards` or any other name
# that differs from the `[string[]]$Boards` PARAMETER only by case. Round 1
# declared `$boards = [ordered]@{}` here: PowerShell variable names are
# case-insensitive, so that local and the typed `-Boards` parameter were the
# SAME binding, and the parameter's `[string[]]` type constraint coerced the
# dictionary into a `System.String[]` (rendering as
# `["System.Collections.Specialized.OrderedDictionary"]` on a dry run and
# throwing on a real one). If you add a per-board collection, either keep this
# array-of-rows shape (assembled into the `boards` object by
# measure_assemble.py, never by this script) or pick a name that cannot
# collide case-insensitively with ANY entry in `param(...)` above.
$boardRows = @()
if (-not $SkipBuild) {
    $env:CARGO_TARGET_DIR = $TargetDir
    foreach ($board in $Boards) {
        Write-Host "== board: $board =="
        $lookup = Invoke-Native -FilePath $Python -Arguments @(
            (Join-Path $RootDir "scripts/target_matrix.py"), "lookup", $board, "flash_layout")
        $layout = (Get-Content $lookup.Log -Raw).Trim()
        if ($layout -eq "n16r8") {
            $csv = Join-Path $RootDir "partitions-16mb.csv"
            $flashSize = "16mb"
        } else {
            $csv = Join-Path $RootDir "partitions.csv"
            $flashSize = "8mb"
        }
        $slot = Get-OtaSlotSize -Csv $csv

        # The release build subsumes Stage B step 2's `cargo check` for this board.
        Invoke-Native -FilePath $Cargo -Arguments @(
            "build", "--release", "-p", "dcentaxe", "--no-default-features",
            "--features", $board) | Out-Null

        $elf = Join-Path $TargetDir "xtensa-esp32s3-espidf/release/dcentaxe"
        $img = Join-Path $ImageDir "$board.bin"
        Invoke-Native -FilePath $Espflash -Arguments @(
            "save-image", "--chip", "esp32s3", "--flash-size", $flashSize,
            "--partition-table", $csv, "--target-app-partition", "ota_0", $elf, $img) | Out-Null

        $bytes = (Get-Item $img).Length
        $sizeRun = Invoke-Native -FilePath $SizeTool -Arguments @($elf)
        $sizeLine = (Get-Content $sizeRun.Log)[1]
        $cols = ($sizeLine -split '\s+') | Where-Object { $_ -ne "" }
        $percent = $null
        if ($slot -gt 0) { $percent = [math]::Round(100.0 * $bytes / $slot, 2) }
        $boardRows += [pscustomobject]@{
            board = $board
            bytes = $bytes
            slot = $slot
            percent_used = $percent
            fits_slot = ($bytes -le $slot)
            text = [int]$cols[0]
            data = [int]$cols[1]
            bss = [int]$cols[2]
            flash_size = $flashSize
            image = ($img.Replace($RepoRoot, "").TrimStart("\", "/") -replace "\\", "/")
        }
        Write-Host "$board`: $bytes / $slot bytes"
        if ($bytes -gt $slot) {
            Write-Host "FAIL: $board image $bytes exceeds its ota_0 slot $slot"
        }
    }
} else {
    Write-Host "== image build SKIPPED (-SkipBuild) =="
}
# One TSV row per board: board, bytes, slot, text, data, bss, flash_size, image.
# Identical to the shell port's boards.tsv.
$BoardsTsv = Join-Path $Work "boards.tsv"
$boardLines = @()
foreach ($row in $boardRows) {
    $boardLines += ("{0}`t{1}`t{2}`t{3}`t{4}`t{5}`t{6}`t{7}" -f `
        $row.board, $row.bytes, $row.slot, $row.text, $row.data, $row.bss, `
        $row.flash_size, $row.image)
}
[System.IO.File]::WriteAllText($BoardsTsv, (($boardLines -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))

# ---------------------------------------------------------------------------
# 4. Per-asset byte table + JSON assembly - delegated, NOT reimplemented.
#
# measure_assemble.py is the ONE writer of measure.json. This port's job ends at
# producing handlers.json / gate.tsv / boards.tsv in $Work; the schema (key set,
# key order, `xtensa_check` always being a list, `boards` always being an object,
# the per-asset table, delta_vs_baseline) belongs to that module alone. Round 1
# hand-built the document here with ConvertTo-Json and it drifted from the shell
# port; tools/check_measure_ports.py now runs both and diffs them.
# ---------------------------------------------------------------------------
$assembleArgs = @(
    (Join-Path $ScriptDir "measure_assemble.py"),
    "--work", $Work,
    "--root", $RootDir,
    "--repo", $RepoRoot,
    "--out", $Out,
    "--lane", $Lane,
    "--baseline", $Baseline
)
$assemble = Invoke-Native -FilePath $Python -Arguments $assembleArgs -AllowFailure
Get-Content $assemble.Log -ErrorAction SilentlyContinue | Write-Host
$assembleExit = $assemble.ExitCode

Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue

if ($assembleExit -ne 0) { exit 1 }
exit 0
