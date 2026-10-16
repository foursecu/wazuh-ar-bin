# ar-sync.ps1 - Wazuh active response (Windows agent), started by ar-sync.cmd
#
# Deploys *.move files from the agent's shared directory into
# active-response\bin, stripping the .move extension:
#
#   ...\ossec-agent\shared\test.cmd.move  ->  ...\ossec-agent\active-response\bin\test.cmd
#
# A file is copied only when the target is missing or its SHA-256 differs.
# Copies go to a temporary file in bin first and are renamed into place,
# so a half-written script is never visible under its final name. Files
# created in bin inherit the bin folder's ACL.

# Extensions never deployed on Windows (Linux-only payloads in a mixed group).
$SkipExtensions = @('.sh')

# The mover never replaces its own files; update them with your install tool.
$ProtectedNames = @('ar-sync.cmd', 'ar-sync.ps1')

# Seconds to wait for another ar-sync run to finish before giving up.
$LockWait = 60

$ErrorActionPreference = 'Stop'

$BinDir    = $PSScriptRoot
$AgentHome = Split-Path -Parent (Split-Path -Parent $BinDir)
$SharedDir = Join-Path $AgentHome 'shared'
$LogFile   = Join-Path $AgentHome 'active-response\active-responses.log'
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Write-ArLog([string]$Message) {
    $line = '{0} active-response/bin/ar-sync.ps1: {1}{2}' -f `
        (Get-Date -Format 'yyyy/MM/dd HH:mm:ss'), $Message, [Environment]::NewLine
    try { [System.IO.File]::AppendAllText($LogFile, $line, $Utf8NoBom) } catch { }
}

function Get-Sha256([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

# Returns the outcome: deployed, updated, current, skipped or failed.
function Sync-MoveFile([System.IO.FileInfo]$File) {
    $name = $File.Name
    $targetName = $name.Substring(0, $name.Length - '.move'.Length)
    $dst = Join-Path $BinDir $targetName

    if ($targetName -eq '' -or $targetName.StartsWith('.')) {
        Write-ArLog "SKIPPED ${name}: invalid target name"
        return 'skipped'
    }
    if ($ProtectedNames -contains $targetName) {
        Write-ArLog "SKIPPED ${name}: the mover does not replace itself"
        return 'skipped'
    }
    if ($SkipExtensions -contains [System.IO.Path]::GetExtension($targetName)) {
        return 'skipped'
    }
    if ($File.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        Write-ArLog "SKIPPED ${name}: not a regular file"
        return 'skipped'
    }
    if (Test-Path -LiteralPath $dst -PathType Container) {
        Write-ArLog "FAILED ${name}: $dst is a directory"
        return 'failed'
    }

    $tmp = $null
    try {
        $srcHash = Get-Sha256 $File.FullName
        $exists = Test-Path -LiteralPath $dst -PathType Leaf
        if ($exists -and (Get-Sha256 $dst) -eq $srcHash) {
            return 'current'
        }

        $tmp = Join-Path $BinDir ('.ar-sync.' + [guid]::NewGuid().ToString('N') + '.tmp')
        [System.IO.File]::Copy($File.FullName, $tmp)
        [System.IO.File]::SetAttributes($tmp, [System.IO.FileAttributes]::Normal)

        # A mismatch means the agent rewrote the file during the copy; the next run retries.
        if ((Get-Sha256 $tmp) -ne $srcHash) {
            Write-ArLog "FAILED ${name}: file changed while copying, will retry on next run"
            return 'failed'
        }

        if ($exists) {
            [System.IO.File]::SetAttributes($dst, [System.IO.FileAttributes]::Normal)
            # Fails while the target is running (e.g. a locked .exe); the next run retries.
            [System.IO.File]::Replace($tmp, $dst, [NullString]::Value)
            $outcome = 'updated'
        } else {
            [System.IO.File]::Move($tmp, $dst)
            $outcome = 'deployed'
        }
        $tmp = $null

        Write-ArLog ('{0} {1} sha256={2}' -f $outcome.ToUpperInvariant(), $targetName, $srcHash)
        return $outcome
    } catch {
        Write-ArLog "FAILED ${name}: $($_.Exception.Message)"
        return 'failed'
    } finally {
        if ($tmp -and (Test-Path -LiteralPath $tmp)) {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }
}

# wazuh-execd writes one JSON line to stdin; this mover does not need it.
try {
    if ([Console]::IsInputRedirected) { $null = [Console]::In.ReadLine() }
} catch { }

Write-ArLog 'Starting'

$mutex = New-Object System.Threading.Mutex($false, 'Global\WazuhArSync')
$hasLock = $false
try {
    $hasLock = $mutex.WaitOne([TimeSpan]::FromSeconds($LockWait))
} catch [System.Threading.AbandonedMutexException] {
    # The previous holder died; the mutex is now ours.
    $hasLock = $true
}
if (-not $hasLock) {
    Write-ArLog "Another ar-sync run is still active after ${LockWait}s, exiting"
    exit 0
}

try {
    $counts = @{ deployed = 0; updated = 0; current = 0; skipped = 0; failed = 0 }
    $files = @(Get-ChildItem -LiteralPath $SharedDir -File |
        Where-Object { $_.Extension -eq '.move' })
    foreach ($file in $files) {
        $counts[(Sync-MoveFile $file)]++
    }
    Write-ArLog ('Ended: deployed={0} updated={1} current={2} skipped={3} failed={4}' -f `
        $counts.deployed, $counts.updated, $counts.current, $counts.skipped, $counts.failed)
} catch {
    Write-ArLog "FAILED: $($_.Exception.Message)"
} finally {
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
exit 0
