# wazuh-ip-block.ps1 - Windows counterpart of wazuh-ip-block.sh, started by wazuh-ip-block.cmd
#
# Reads one line of Wazuh active-response JSON from STDIN and blocks or
# unblocks an IP address in Windows Defender Firewall. Full documentation:
# wazuh-ip-block.md
#
#   Manual API mode : parameters.extra_args = ["block"|"add"|"unblock"|"delete", "<ip>" [, "<seconds>"]]
#                     (an optional timeout makes a manual block expire on its own)
#   Native AR mode  : command = add|delete, parameters.alert.data.srcip
#                     (else parameters.alert.data.win.eventdata.ipAddress)
#
# Needs Windows PowerShell 5.1 on Windows 8 / Server 2012 or later (the
# NetSecurity, NetTCPIP, DnsClient and ScheduledTasks modules), run as SYSTEM
# or an administrator.
#
# A block is two rules in group "Wazuh active response", one inbound and one
# outbound, for every profile and interface. Block rules win over allow rules
# in Windows Defender Firewall. Windows re-checks open connections against new
# rules, so connections that are already open stop working too. A block is:
#   - runtime only: a startup task removes every block after a reboot, like
#     Wazuh's own timeouts (Windows keeps firewall rules across reboots),
#   - in both directions,
#   - checked: the rules are read back, a half-applied change is rolled back.
# Runs are serialized by a mutex; a repeated block only adds what is missing.
# Before it changes anything it checks that the firewall is running, enabled
# for at least one profile, and not told by Group Policy to ignore local rules.
#
# A block is refused (unblock is always allowed) when the address is:
#   - special: unspecified, loopback, link-local, multicast, broadcast or
#     reserved, in any spelling (IPv6 is compared as bytes)
#   - on the never-block list:
#       * the Wazuh manager address(es) from ossec.conf <client><server><address>
#         (host names are resolved)
#       * this machine's own addresses, default gateways and DNS servers
#       * entries (IP or CIDR, one per line, # comments) in
#           <agent>\wazuh-ip-block.never-block           (local)
#           <agent>\shared\wazuh-ip-block.never-block    (from the agent group)


#PUT /active-response?agents_list=???
#{
#  "command": "!wazuh-ip-block.cmd",
#  "arguments": ["block", "1.1.1.1"]
#}

#PUT /active-response?agents_list=???
#{
#  "command": "!wazuh-ip-block.cmd",
#  "arguments": ["block", "1.1.1.1", "3600"]
#}

#PUT /active-response?agents_list=???
#{
#  "command": "!wazuh-ip-block.cmd",
#  "arguments": ["unblock", "1.1.1.1"]
#}

# -Unblock and -BootCleanup are for the scheduled tasks this script creates.
param(
    [string]$Unblock,
    [switch]$BootCleanup
)

# Set to $true to also log firewall check details.
$DebugLog = $false

# Seconds to wait for another run to finish before giving up.
$LockWait = 60

# Longest accepted timeout for a manual block (one year).
$MaxTimeout = 31536000

$RuleGroup    = 'Wazuh active response'
$RulePrefix   = 'WazuhIPBlock'
$TaskPath     = '\Wazuh\'
$BootTaskName = 'IP block - clear at startup'
$TimerPrefix  = 'IP block - unblock '

$ErrorActionPreference = 'Stop'

$ScriptName = 'wazuh-ip-block.cmd'
$SelfPath   = $PSCommandPath
$BinDir     = $PSScriptRoot
$AgentHome  = Split-Path -Parent (Split-Path -Parent $BinDir)
# the log every active response writes to; the agent forwards it to the manager
$LogFile    = Join-Path $AgentHome 'active-response\active-responses.log'
$OssecConf  = Join-Path $AgentHome 'ossec.conf'
$NeverBlockFiles = @(
    (Join-Path $AgentHome 'wazuh-ip-block.never-block'),
    (Join-Path $AgentHome 'shared\wazuh-ip-block.never-block')
)
$Utf8NoBom  = New-Object System.Text.UTF8Encoding($false)

$script:ExitCode = 0

function Write-ArLog([string]$Message) {
    $line = '{0} active-response/bin/{1}: {2}{3}' -f `
        (Get-Date -Format 'yyyy/MM/dd HH:mm:ss'), $ScriptName, $Message, [Environment]::NewLine
    # another active response may be writing at the same moment
    for ($i = 0; $i -lt 5; $i++) {
        try {
            [System.IO.File]::AppendAllText($LogFile, $line, $Utf8NoBom)
            return
        } catch {
            Start-Sleep -Milliseconds 100
        }
    }
}

function Write-ArDebug([string]$Message) {
    if ($DebugLog) { Write-ArLog $Message }
}

# Ends the run: logs, sets the exit code and unwinds to the main block.
function Stop-Run([string]$Message, [int]$Code) {
    if ($Code -eq 0) { Write-ArLog $Message } else { Write-ArLog "ERROR: $Message" }
    $script:ExitCode = $Code
    throw (New-Object System.OperationCanceledException $Message)
}

function Fail([string]$Message) {
    Stop-Run $Message 1
}

# ---------------------------------------------------------------------------
# Addresses
# ---------------------------------------------------------------------------

function New-IpInfo([int]$Family, [byte[]]$Bytes) {
    if ($Family -eq 4) {
        $text = ($Bytes | ForEach-Object { [string]$_ }) -join '.'
    } else {
        $text = (New-Object System.Net.IPAddress (,$Bytes)).ToString()
    }
    New-Object PSObject -Property @{ Family = $Family; Bytes = $Bytes; Address = $text }
}

function Test-StrictIpv4([string]$Text) {
    if ($Text -notmatch '^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$') { return $false }
    foreach ($octet in $Text.Split('.')) {
        if ([int]$octet -gt 255) { return $false }
    }
    return $true
}

# Canonical form of an IPv4 or IPv6 address, or $null. Strict: no masks, no
# zone index, no shortened or octal IPv4 forms. An IPv4-mapped IPv6 address
# (::ffff:a.b.c.d in any spelling) is really an IPv4 client and becomes IPv4.
function ConvertTo-IpInfo([string]$Text) {
    if ($null -eq $Text) { return $null }
    $t = $Text.Trim().ToLowerInvariant()
    if (Test-StrictIpv4 $t) {
        return New-IpInfo 4 ([byte[]]($t.Split('.') | ForEach-Object { [int]$_ }))
    }
    if ($t -notmatch '^[0-9a-f:.]{2,45}$' -or $t -notmatch ':.*:') { return $null }
    if ($t.Contains('.') -and -not (Test-StrictIpv4 $t.Substring($t.LastIndexOf(':') + 1))) { return $null }
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($t, [ref]$ip)) { return $null }
    if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetworkV6) { return $null }
    $b = $ip.GetAddressBytes()
    $mapped = $b[10] -eq 255 -and $b[11] -eq 255
    for ($i = 0; $i -lt 10; $i++) { if ($b[$i] -ne 0) { $mapped = $false } }
    if ($mapped) { return New-IpInfo 4 ([byte[]]$b[12..15]) }
    return New-IpInfo 6 $b
}

# Why an address must never be blocked, or $null.
function Get-SpecialReason($Info) {
    $b = $Info.Bytes
    if ($Info.Family -eq 4) {
        if ($b[0] -eq 0)   { return "'this network' address (0.0.0.0/8)" }
        if ($b[0] -eq 127) { return 'loopback address (127.0.0.0/8)' }
        if ($b[0] -eq 169 -and $b[1] -eq 254) {
            return 'link-local address (169.254.0.0/16, includes cloud metadata services)'
        }
        if ($b[0] -ge 224 -and $b[0] -le 239) { return 'multicast address (224.0.0.0/4)' }
        if ($b[0] -ge 240) { return 'reserved or broadcast address (240.0.0.0/4)' }
        return $null
    }
    $zero96 = $true
    for ($i = 0; $i -lt 12; $i++) { if ($b[$i] -ne 0) { $zero96 = $false } }
    if ($zero96) { return 'unspecified, loopback or IPv4-compatible address (::/96)' }
    if ($b[0] -eq 0xfe -and ($b[1] -band 0xc0) -eq 0x80) { return 'link-local address (fe80::/10)' }
    if ($b[0] -eq 0xff) { return 'multicast address (ff00::/8)' }
    return $null
}

# Is address $Info inside entry $Entry (an IP or CIDR)?
function Test-IpInEntry($Info, [string]$Entry) {
    $parts = $Entry.Split('/')
    if ($parts.Count -gt 2) { return $false }
    $net = ConvertTo-IpInfo ($parts[0].Split('%')[0])
    if ($null -eq $net -or $net.Family -ne $Info.Family) { return $false }
    $max = $Info.Bytes.Length * 8
    $len = $max
    if ($parts.Count -eq 2) {
        if ($parts[1] -notmatch '^[0-9]{1,3}$') { return $false }
        $len = [int]$parts[1]
        if ($len -gt $max) { return $false }
    }
    $full = [math]::Floor($len / 8)
    for ($i = 0; $i -lt $full; $i++) {
        if ($Info.Bytes[$i] -ne $net.Bytes[$i]) { return $false }
    }
    $bits = $len % 8
    if ($bits -eq 0) { return $true }
    $mask = (0xff -shl (8 - $bits)) -band 0xff
    return ($Info.Bytes[$full] -band $mask) -eq ($net.Bytes[$full] -band $mask)
}

# Every address or network never to block, as objects with Source and Entry.
function Get-NeverBlockEntries {
    $entries = New-Object System.Collections.ArrayList
    function Add-Entry([string]$Source, [string]$Entry) {
        if ($Entry) { [void]$entries.Add((New-Object PSObject -Property @{ Source = $Source; Entry = $Entry.Trim() })) }
    }

    # ossec.conf is not always strict XML, so read <client> sections as text
    if (Test-Path -LiteralPath $OssecConf) {
        $conf = [System.IO.File]::ReadAllText($OssecConf)
        foreach ($client in [regex]::Matches($conf, '(?s)<client>(.*?)</client>')) {
            foreach ($m in [regex]::Matches($client.Groups[1].Value, '<address>\s*([^<\s]+)\s*</address>')) {
                $manager = $m.Groups[1].Value
                if (ConvertTo-IpInfo $manager) {
                    Add-Entry 'manager' $manager
                    continue
                }
                try {
                    foreach ($a in [System.Net.Dns]::GetHostAddresses($manager)) {
                        Add-Entry 'manager' $a.IPAddressToString.Split('%')[0]
                    }
                } catch {
                    Write-ArLog "WARNING: cannot resolve manager address $manager; it is not protected"
                }
            }
        }
    } else {
        Write-ArLog "WARNING: cannot read $OssecConf; manager address is not protected"
    }

    try {
        foreach ($a in Get-NetIPAddress -ErrorAction Stop) { Add-Entry 'local-address' ([string]$a.IPAddress).Split('%')[0] }
    } catch { Write-ArDebug "Get-NetIPAddress failed: $($_.Exception.Message)" }
    try {
        foreach ($r in Get-NetRoute -DestinationPrefix '0.0.0.0/0', '::/0' -ErrorAction Stop) {
            if ($r.NextHop -and $r.NextHop -ne '0.0.0.0' -and $r.NextHop -ne '::') { Add-Entry 'gateway' $r.NextHop }
        }
    } catch { Write-ArDebug "Get-NetRoute failed: $($_.Exception.Message)" }
    try {
        foreach ($d in Get-DnsClientServerAddress -ErrorAction Stop) {
            foreach ($s in $d.ServerAddresses) { Add-Entry 'dns-server' $s }
        }
    } catch { Write-ArDebug "Get-DnsClientServerAddress failed: $($_.Exception.Message)" }

    foreach ($file in $NeverBlockFiles) {
        if (-not (Test-Path -LiteralPath $file)) { continue }
        foreach ($line in [System.IO.File]::ReadAllLines($file)) {
            Add-Entry $file ($line -replace '#.*$', '').Trim()
        }
    }
    return $entries
}

# The first never-block entry that covers the address, as "entry (source)", or $null.
function Get-NeverBlockHit($Info) {
    foreach ($e in Get-NeverBlockEntries) {
        if (Test-IpInEntry $Info $e.Entry) { return "$($e.Entry) ($($e.Source))" }
    }
    return $null
}

# ---------------------------------------------------------------------------
# Windows Defender Firewall
# ---------------------------------------------------------------------------

# Why the firewall cannot enforce a block, or $null.
function Get-FirewallProblem {
    if (-not (Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue)) {
        return 'the NetSecurity module is not available (needs Windows 8 / Server 2012 or later)'
    }
    $svc = Get-Service -Name mpssvc -ErrorAction SilentlyContinue
    if (-not $svc -or [string]$svc.Status -ne 'Running') {
        return 'the Windows Defender Firewall service (mpssvc) is not running'
    }
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
    $on = @($profiles | Where-Object { [string]$_.Enabled -eq 'True' })
    if ($on.Count -eq 0) { return 'Windows Defender Firewall is turned off for every profile' }
    # Group Policy can tell the firewall to ignore locally created rules
    $ignored = @($on | Where-Object { [string]$_.AllowLocalFirewallRules -eq 'False' })
    if ($ignored.Count -gt 0) {
        return 'Group Policy makes the firewall ignore local rules (AllowLocalFirewallRules=False) on profile(s): ' +
            (($ignored | ForEach-Object { $_.Name }) -join ', ')
    }
    $off = @($profiles | Where-Object { [string]$_.Enabled -ne 'True' })
    if ($off.Count -gt 0) {
        Write-ArLog ('WARNING: the firewall is off for profile(s) {0}; the block does not apply on networks of that type' -f
            (($off | ForEach-Object { $_.Name }) -join ', '))
    }
    Write-ArDebug ('Firewall profiles on: {0}' -f (($on | ForEach-Object { $_.Name }) -join ', '))
    return $null
}

function Get-RuleName([string]$Direction) {
    '{0}_{1}_{2}' -f $RulePrefix, $IpInfo.Address.Replace(':', '_'), $Direction
}

# Is this rule an enabled block of exactly this address, for every profile?
function Test-BlockRule($Rule) {
    if ([string]$Rule.Enabled -ne 'True' -or [string]$Rule.Action -ne 'Block' -or [string]$Rule.Profile -ne 'Any') {
        return $false
    }
    $max = $IpInfo.Bytes.Length * 8
    $remote = @((Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $Rule).RemoteAddress)
    if ($remote.Count -ne 1) { return $false }
    $parts = ([string]$remote[0]).Split('/')
    $addr = ConvertTo-IpInfo $parts[0]
    if ($null -eq $addr -or $addr.Address -ne $IpInfo.Address) { return $false }
    return $parts.Count -eq 1 -or $parts[1] -eq [string]$max -or $parts[1] -eq '255.255.255.255'
}

function Get-BlockRule([string]$Direction) {
    Get-NetFirewallRule -Name (Get-RuleName $Direction) -ErrorAction SilentlyContinue
}

# Adds only what is missing, so a repeated block never opens a gap. On
# failure only the rules this run added are rolled back.
function Add-Block {
    $added = @()
    foreach ($dir in 'Inbound', 'Outbound') {
        $name = Get-RuleName $dir
        $rule = Get-BlockRule $dir
        if ($rule -and (Test-BlockRule $rule)) { continue }
        try {
            # a rule with this name but other settings is replaced
            if ($rule) { Remove-NetFirewallRule -Name $name -ErrorAction Stop }
            New-NetFirewallRule -Name $name -DisplayName ('Wazuh IP block {0} ({1})' -f $IpInfo.Address, $dir.ToLowerInvariant()) `
                -Group $RuleGroup -Description 'Created by the Wazuh active response wazuh-ip-block' `
                -Direction $dir -Action Block -RemoteAddress $IpInfo.Address -Profile Any -Enabled True `
                -ErrorAction Stop | Out-Null
            $added += $name
        } catch {
            Write-ArLog "ERROR adding $dir rule for $($IpInfo.Address) : $($_.Exception.Message)"
            Undo-Rules $added
            return $false
        }
    }
    foreach ($dir in 'Inbound', 'Outbound') {
        $rule = Get-BlockRule $dir
        if (-not $rule -or -not (Test-BlockRule $rule)) {
            Write-ArLog "ERROR: $dir rule for $($IpInfo.Address) not found after adding it"
            Undo-Rules $added
            return $false
        }
    }
    return $true
}

function Undo-Rules([string[]]$Names) {
    foreach ($n in $Names) { Remove-NetFirewallRule -Name $n -ErrorAction SilentlyContinue }
}

# Removes both rules, whether or not the firewall is usable right now.
function Remove-Block {
    $ok = $true
    foreach ($dir in 'Inbound', 'Outbound') {
        $name = Get-RuleName $dir
        if (-not (Get-BlockRule $dir)) { continue }
        try {
            Remove-NetFirewallRule -Name $name -ErrorAction Stop
        } catch {
            Write-ArLog "DELETE: Remove-NetFirewallRule $name said: $($_.Exception.Message)"
        }
        if (Get-BlockRule $dir) {
            Write-ArLog "ERROR: $dir rule for $($IpInfo.Address) is still present after removal"
            $ok = $false
        }
    }
    return $ok
}

# ---------------------------------------------------------------------------
# Scheduled tasks: clear blocks at startup, expire manual blocks
# ---------------------------------------------------------------------------

function New-ArTask([string]$Arguments, $Trigger, [string]$Description) {
    $ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $action = New-ScheduledTaskAction -Execute $ps -Argument (
        '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" {1}' -f $SelfPath, $Arguments)
    $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
    New-ScheduledTask -Action $action -Trigger $Trigger -Principal $principal -Settings $settings -Description $Description
}

# Windows keeps firewall rules across reboots. Without this task a block
# whose Wazuh timeout was pending at reboot would stay forever.
function Install-BootTask {
    if (Get-ScheduledTask -TaskPath $TaskPath -TaskName $BootTaskName -ErrorAction SilentlyContinue) { return }
    try {
        $task = New-ArTask '-BootCleanup' (New-ScheduledTaskTrigger -AtStartup) `
            'Removes every Wazuh IP block at startup, so blocks are runtime only (wazuh-ip-block).'
        Register-ScheduledTask -TaskPath $TaskPath -TaskName $BootTaskName -InputObject $task -Force | Out-Null
        Write-ArLog "Registered startup task $TaskPath$BootTaskName"
    } catch {
        Write-ArLog "WARNING: cannot register the startup task, blocks will survive a reboot: $($_.Exception.Message)"
    }
}

function Get-TimerName {
    $TimerPrefix + $IpInfo.Address.Replace(':', '_')
}

function Remove-Timer {
    Unregister-ScheduledTask -TaskPath $TaskPath -TaskName (Get-TimerName) -Confirm:$false -ErrorAction SilentlyContinue
}

# The newest block decides: registering with -Force replaces an older timer.
function Register-Timer([int]$Seconds) {
    try {
        $task = New-ArTask ('-Unblock "{0}"' -f $IpInfo.Address) (New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds($Seconds)) `
            "Unblocks $($IpInfo.Address) when its manual block expires (wazuh-ip-block)."
        Register-ScheduledTask -TaskPath $TaskPath -TaskName (Get-TimerName) -InputObject $task -Force | Out-Null
    } catch {
        Write-ArLog "ERROR: cannot register the expiry task, $($IpInfo.Address) stays blocked until unblocked by hand: $($_.Exception.Message)"
        return $false
    }
    Write-ArLog "Timer: $($IpInfo.Address) will be unblocked in ${Seconds}s"
    return $true
}

function Invoke-BootCleanup {
    $rules = @(Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue)
    foreach ($r in $rules) { Remove-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue }
    $left = @(Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue).Count
    $timers = @(Get-ScheduledTask -TaskPath $TaskPath -ErrorAction SilentlyContinue |
        Where-Object { $_.TaskName.StartsWith($TimerPrefix) })
    foreach ($t in $timers) {
        Unregister-ScheduledTask -TaskPath $TaskPath -TaskName $t.TaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    if ($left -gt 0) { Fail "startup cleanup: $left rule(s) in group '$RuleGroup' could not be removed" }
    Write-ArLog "Startup cleanup: removed $($rules.Count) rule(s) and $($timers.Count) expiry task(s)"
}

# ---------------------------------------------------------------------------
# Lock
# ---------------------------------------------------------------------------

$script:Mutex = $null
function Get-Lock {
    $script:Mutex = New-Object System.Threading.Mutex($false, 'Global\WazuhIPBlock')
    $locked = $false
    try {
        $locked = $script:Mutex.WaitOne([TimeSpan]::FromSeconds($LockWait))
    } catch [System.Threading.AbandonedMutexException] {
        # the previous holder died; the mutex is now ours
        $locked = $true
    }
    if (-not $locked) {
        $script:Mutex.Dispose()
        $script:Mutex = $null
        Fail "another run still holds the lock after ${LockWait}s"
    }
}

function Exit-Lock {
    if ($script:Mutex) {
        try { $script:Mutex.ReleaseMutex() } catch { }
        $script:Mutex.Dispose()
        $script:Mutex = $null
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

try {
    if ($BootCleanup) {
        Get-Lock
        Invoke-BootCleanup
        return
    }

    $Timeout = $null
    if ($Unblock) {
        # started by an expiry task
        $Mode = 'timer'
        $Command = 'delete'
        $Operation = 'delete'
        $RawIp = $Unblock
        Write-ArLog "Timer: delete $RawIp"
    } else {
        $Stdin = New-Object System.IO.StreamReader([Console]::OpenStandardInput())
        $InputLine = $Stdin.ReadLine()
        if (-not $InputLine) { Fail 'Empty input' }
        try {
            $Message = $InputLine | ConvertFrom-Json
        } catch {
            Fail 'Input is not valid JSON'
        }
        $Command = [string]$Message.command
        if (-not $Command) { Fail 'Missing command' }
        $Origin = [string]$Message.origin.module
        $RuleId = [string]$Message.parameters.alert.rule.id
        $ExtraArgs = @($Message.parameters.extra_args)

        $ArgOp = if ($ExtraArgs.Count -ge 1) { [string]$ExtraArgs[0] } else { '' }
        $ArgIp = if ($ExtraArgs.Count -ge 2) { [string]$ExtraArgs[1] } else { '' }
        $ArgTimeout = if ($ExtraArgs.Count -ge 3) { [string]$ExtraArgs[2] } else { '' }

        if ($ArgOp -and $ArgIp) {
            $Mode = 'manual'
            switch ($ArgOp.ToLowerInvariant()) {
                { $_ -in 'add', 'block' }      { $Operation = 'add' }
                { $_ -in 'delete', 'unblock' } { $Operation = 'delete' }
                default { Fail "Invalid extra_args operation: $ArgOp" }
            }
            $RawIp = $ArgIp
            if ($ArgTimeout) {
                if ($Operation -ne 'add') { Fail "A timeout is only valid for block: $ArgTimeout" }
                if ($ArgTimeout -notmatch '^[1-9][0-9]{0,8}$' -or [int]$ArgTimeout -gt $MaxTimeout) {
                    Fail "Invalid timeout (whole seconds, 1-$MaxTimeout): $ArgTimeout"
                }
                $Timeout = [int]$ArgTimeout
            }
            $forText = if ($Timeout) { " for ${Timeout}s" } else { '' }
            $originText = if ($Origin) { $Origin } else { 'unknown origin' }
            Write-ArLog "Manual mode ($originText): $Operation $RawIp$forText"
        } else {
            $Mode = 'native'
            $Operation = $Command.ToLowerInvariant()
            $RawIp = [string]$Message.parameters.alert.data.srcip
            # Windows logon events carry the client address here instead
            if (-not $RawIp) { $RawIp = [string]$Message.parameters.alert.data.win.eventdata.ipAddress }
            if (-not $RawIp) { Fail 'Missing parameters.alert.data.srcip' }
            $ruleText = if ($RuleId) { $RuleId } else { 'unknown' }
            Write-ArLog "Native AR mode: $Operation $RawIp (rule $ruleText)"
        }
        if ($Operation -notin 'add', 'delete') { Fail "Unsupported command: $Operation" }
    }

    $IpInfo = ConvertTo-IpInfo $RawIp
    if ($null -eq $IpInfo) { Fail "Invalid IP address: $RawIp" }
    $IP = $IpInfo.Address

    # Unblocking stays possible for every valid address, so a mistaken block
    # can always be removed.
    if ($Operation -eq 'add') {
        $reason = Get-SpecialReason $IpInfo
        if ($reason) { Fail "REFUSED to block ${IP}: $reason" }
        $hit = Get-NeverBlockHit $IpInfo
        if ($hit) { Fail "REFUSED to block ${IP}: on the never-block list as $hit" }
    }

    # Wazuh 4.2+ protocol for a rule-triggered "add": send the key (the
    # address) and wait for "continue" or "abort". wazuh-execd answers
    # "abort" while the address already has a pending timed block. Manual API
    # calls skip it: they are not tracked by execd.
    if ($Mode -eq 'native' -and $Operation -eq 'add' -and $Command -eq 'add' -and [Console]::IsInputRedirected) {
        $keys = '{"version":1,"origin":{"name":"' + $ScriptName + '","module":"active-response"},' +
            '"command":"check_keys","parameters":{"keys":["' + $IP + '"]}}'
        [Console]::Out.WriteLine($keys)
        [Console]::Out.Flush()
        $read = $Stdin.ReadLineAsync()
        $reply = $null
        if ($read.Wait(30000)) { $reply = $read.Result }
        if (-not $reply) {
            Write-ArDebug 'no check_keys reply (not started by wazuh-execd?), continuing'
        } else {
            $answer = $null
            try { $answer = ($reply | ConvertFrom-Json).command } catch { }
            if ($answer -eq 'abort') { Stop-Run "execd says abort: $IP is already blocked by an active timed block" 0 }
        }
    }

    # Serialize runs: alert bursts start many at once.
    Get-Lock

    if ($Operation -eq 'add') {
        $problem = Get-FirewallProblem
        if ($problem) { Fail "cannot block ${IP}: $problem" }
        Write-ArLog 'Firewall in use: Windows Defender Firewall'
        Write-ArLog "ADD requested: IP=$IP"
        if (-not (Add-Block)) { Fail "$IP is NOT blocked" }
        Install-BootTask
        # the newest block decides when the address is released
        if ($Mode -eq 'manual' -and $Timeout) {
            if (-not (Register-Timer $Timeout)) { Fail "$IP is blocked, but without its expiry" }
        } else {
            Remove-Timer
        }
        $forText = if ($Timeout) { " for ${Timeout}s" } else { '' }
        Write-ArLog "SUCCESS: IP blocked: $IP firewall=Windows Defender Firewall$forText"
    } else {
        Write-ArLog "DELETE requested: IP=$IP"
        Remove-Timer
        if (-not (Remove-Block)) { Fail "$IP is NOT fully unblocked" }
        Write-ArLog "DELETE done: IP=$IP"
    }
} catch [System.OperationCanceledException] {
    # Stop-Run has logged and set the exit code
} catch {
    Write-ArLog "ERROR: $($_.Exception.Message)"
    $script:ExitCode = 1
} finally {
    Exit-Lock
}
exit $script:ExitCode
