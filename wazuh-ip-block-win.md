# wazuh-ip-block (Windows)

A Wazuh active-response script for Windows agents. It blocks or unblocks one IPv4 or IPv6 address
in Windows Defender Firewall. It's the Windows counterpart of `linux/wazuh-ip-block.sh`:
- same API arguments;
- same safety checks;
- same never-block list (same file name);
- same log format;
- same runtime-only blocks.

It works in two ways:
- triggered by **Wazuh rules** (native active response, with Wazuh's timeouts), or
- called **manually through the Wazuh API**, with an optional expiry.

| File | Role |
|---|---|
| `wazuh-ip-block.cmd` | entry point that Wazuh runs. It starts the 64-bit Windows PowerShell. |
| `wazuh-ip-block.ps1` | does the work |

---

## Contents

1. [What a block does](#1-what-a-block-does)
2. [Differences from the Linux script](#2-differences-from-the-linux-script)
3. [Requirements](#3-requirements)
4. [Installation](#4-installation)
5. [Usage](#5-usage)
6. [Safety: addresses that are never blocked](#6-safety-addresses-that-are-never-blocked)
7. [How blocks are made](#7-how-blocks-are-made)
8. [Unblocking, expiry and reboot](#8-unblocking-expiry-and-reboot)
9. [Logging](#9-logging)
10. [Files, rules, tasks and settings](#10-files-rules-tasks-and-settings)
11. [Exit codes](#11-exit-codes)
12. [Checking blocks by hand](#12-checking-blocks-by-hand)
13. [Testing done](#13-testing-done)
14. [Known gaps and limitations](#14-known-gaps-and-limitations)
15. [Removing the script](#15-removing-the-script)

---

## 1. What a block does

| Property | Meaning |
|---|---|
| **Both directions** | one inbound and one outbound block rule for the address |
| **Every network** | the rules apply to all profiles (Domain, Private, Public) and all interfaces |
| **Wins over allow rules** | in Windows Defender Firewall, block rules take precedence over allow rules |
| **Immediate** | Windows re-checks open connections against new rules (see section 14), so connections that are already open stop working too |
| **Runtime only** | Windows keeps firewall rules across reboots, so a startup task removes every block. This matches how Wazuh handles timeouts. |
| **Repeatable** | blocking an address that's already blocked only adds what's missing; the address is never briefly unblocked |
| **Checked** | the rules are read back after every change; a half-applied change is rolled back |

Before blocking, the script refuses special addresses and anything on the never-block list
(section 6). Unblocking is always allowed for any valid address.

---

## 2. Differences from the Linux script

| Topic | Linux | Windows |
|---|---|---|
| Firewall | detects firewalld / ufw / iptables / nftables | Windows Defender Firewall only |
| Forwarded traffic (Docker, routing) | blocked by the guard rules | **not covered** (section 14) |
| Open connections | dropped by guard rules + `conntrack -D` | Windows re-checks them against new rules |
| Runtime only | firewall rules are lost at reboot anyway | a startup task removes them |
| Manual expiry | detached `sleep` process | one-time scheduled task, running as SYSTEM |
| Lock | `var/run/wazuh-ip-block.lock` directory | named mutex `Global\WazuhIPBlock` |
| Message parsing | `jq` or built-in parser | `ConvertFrom-Json` |
| Native-mode address | `data.srcip` | `data.srcip`, else `data.win.eventdata.ipAddress` (Windows logon events) |
| Firewall checks | firewall installed and running | service running, at least one profile on, Group Policy not ignoring local rules |
| AR command name | `!wazuh-ip-block.sh` | `!wazuh-ip-block.cmd` |

---

## 3. Requirements

- **Windows 8 / Server 2012 or later**, with Windows PowerShell 5.1. These are the defaults on
  Windows 10/11 and Server 2016–2025. The modules NetSecurity, NetTCPIP, DnsClient and
  ScheduledTasks are built in.
- **Runs as SYSTEM.** The Wazuh agent service does this.
- **Windows Defender Firewall:** the `mpssvc` service running, and at least one profile enabled.
- **Execution policy:** the wrapper uses `-ExecutionPolicy Bypass`. If Group Policy enforces
  `AllSigned`, that wins: **sign `wazuh-ip-block.ps1`**.

---

## 4. Installation

### 4.1 On each agent

Copy both files to `C:\Program Files (x86)\ossec-agent\active-response\bin\`.

**Central distribution with ar-sync:** put them on the manager as
`/var/ossec/etc/shared/<group>/wazuh-ip-block.cmd.move` and `wazuh-ip-block.ps1.move`. The
Windows ar-sync mover installs both; the Linux mover skips `.cmd` and `.ps1`.

The startup task (section 8.3) is created automatically on the first block.

### 4.2 Rule-triggered blocks (optional)

On the **manager**, in `/var/ossec/etc/ossec.conf`:

```xml
<command>
  <name>wazuh-ip-block-win</name>
  <executable>wazuh-ip-block.cmd</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <command>wazuh-ip-block-win</command>
  <location>local</location>
  <rules_id>60204</rules_id>   <!-- e.g. multiple Windows logon failures -->
  <timeout>600</timeout>
</active-response>
```

- **Mixed groups:** if the same rules fire for Linux and Windows agents, configure the Linux
  command (`wazuh-ip-block.sh`) and this one as separate `<command>` blocks. Each agent only
  runs the file it has.
- **Repeat offenders:** add `<repeated_offenders>` to the agent's `<active-response>` section for
  longer blocks. This works because of the handshake (section 5.3).

### 4.3 Never-block list (recommended)

See section 6. A `wazuh-ip-block.never-block` file in the manager's group folder works for both
the Linux and the Windows script.

---

## 5. Usage

### 5.1 Rule-triggered (native mode)

Wazuh sends `"command": "add"` with the alert. The address is taken from:
1. `parameters.alert.data.srcip`, otherwise
2. `parameters.alert.data.win.eventdata.ipAddress`, used by Windows logon events such as 4625.

Values like `-` or `::1` are rejected. After the `<timeout>`, Wazuh sends `"command": "delete"`.

### 5.2 Manual, through the Wazuh API (manual mode)

```
PUT /active-response?agents_list=005,006
{ "command": "!wazuh-ip-block.cmd", "arguments": ["block", "203.0.113.7"] }

PUT /active-response?agents_list=005,006
{ "command": "!wazuh-ip-block.cmd", "arguments": ["block", "203.0.113.7", "3600"] }

PUT /active-response?agents_list=005,006
{ "command": "!wazuh-ip-block.cmd", "arguments": ["unblock", "203.0.113.7"] }
```

| `arguments` | Effect |
|---|---|
| `["block", "<ip>"]` (or `add`) | Block until unblocked or rebooted. Cancels a pending expiry for that address. |
| `["block", "<ip>", "<seconds>"]` | Block, and unblock automatically after `<seconds>` (1 to 31536000, no leading zeros). |
| `["unblock", "<ip>"]` (or `delete`) | Unblock, and cancel any pending expiry. |

- **Case:** the operation names are case-insensitive.
- **Address formats:** IPv6 may be written in any form (uppercase, written out in full,
  IPv4-mapped).
- **Not accepted:** network masks (`/24`), zone indexes (`%12`), shortened IPv4 (`1.2.3`) and
  leading zeros (`01.2.3.4`).

### 5.3 The handshake with wazuh-execd (`check_keys`)

**When it happens:** for a rule-triggered `add`.

**What it does:**
1. The script writes the address to stdout as `check_keys` and waits up to 30 s for the reply.
2. If execd replies `abort`, meaning the address already has a pending timed block, the script
   exits 0 without touching the firewall.

**When it's skipped:** for manual calls, unblocks and runs without redirected stdin. Nothing else
is written to stdout.

### 5.4 Manual test on an agent (elevated PowerShell)

```powershell
'{"command":"add","parameters":{"extra_args":["block","203.0.113.7","60"]}}' |
  & 'C:\Program Files (x86)\ossec-agent\active-response\bin\wazuh-ip-block.cmd'; "rc=$LASTEXITCODE"
Get-Content 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log' -Tail 10
```

---

## 6. Safety: addresses that are never blocked

A **block** is refused with exit code 1 and a `REFUSED to block ...` log line for the addresses
below. An **unblock** is always allowed.

### 6.1 Special addresses (in any spelling)

| IPv4 | IPv6 |
|---|---|
| `0.0.0.0/8` | `::/96`: `::`, loopback `::1`, IPv4-compatible |
| `127.0.0.0/8` (loopback) | `fe80::/10` (link-local) |
| `169.254.0.0/16` (link-local, **includes cloud metadata 169.254.169.254**) | `ff00::/8` (multicast) |
| `224.0.0.0/4` (multicast) | |
| `240.0.0.0/4` (reserved, including `255.255.255.255`) | |

IPv6 addresses are compared as bytes, so every spelling is caught. IPv4-mapped addresses are
checked as IPv4.

### 6.2 The never-block list

Built from these sources on every block:

| Source | Details |
|---|---|
| **Wazuh manager** | every `<address>` in `<client><server>` of `C:\Program Files (x86)\ossec-agent\ossec.conf`. Host names are resolved, so all their addresses are protected. |
| **The agent itself** | own addresses (`Get-NetIPAddress`), default gateways (`Get-NetRoute`), DNS servers (`Get-DnsClientServerAddress`) |
| **Local list** | `C:\Program Files (x86)\ossec-agent\wazuh-ip-block.never-block` |
| **Central list** | `C:\Program Files (x86)\ossec-agent\shared\wazuh-ip-block.never-block`, which Wazuh copies from the manager's group folder |

List format (the same as on Linux): one IPv4/IPv6 address or CIDR range per line, `#` comments
allowed.

```
# admin networks
10.20.0.0/16        # jump hosts
2001:db8:aaaa::/48
```

---

## 7. How blocks are made

Two rules per address in group **`Wazuh active response`**:

| Rule name (`-Name`) | Display name | Settings |
|---|---|---|
| `WazuhIPBlock_<ip>_Inbound` | `Wazuh IP block <ip> (inbound)` | Direction Inbound, Action Block, RemoteAddress `<ip>`, Profile Any, Enabled |
| `WazuhIPBlock_<ip>_Outbound` | `Wazuh IP block <ip> (outbound)` | Direction Outbound, the same otherwise |

In rule and task names, `:` in IPv6 addresses is written as `_`.

**Before a block, the script checks the firewall and refuses with exit 1 if:**
- the `mpssvc` service isn't running;
- the firewall is off for **every** profile;
- Group Policy makes an enabled profile ignore locally created rules
  (`AllowLocalFirewallRules = False`). The rules would exist but do nothing.

**Warning only:** a profile that's turned off is logged as a `WARNING`, because the block doesn't
apply on networks of that type.

**A repeated block** leaves correct rules alone. A rule with the right name but wrong settings
(e.g. disabled) is replaced. If the second rule can't be created, the first one from this run is
removed again.

---

## 8. Unblocking, expiry and reboot

### 8.1 Unblock

Both rules are removed and checked to be gone, and any expiry task for the address is cancelled.
This also works while the firewall service is stopped, as far as Windows allows it.

### 8.2 Expiry of manual blocks

A block with `<seconds>` registers the one-time task
`\Wazuh\IP block - unblock <ip>`. It runs as SYSTEM at the expiry time and calls
`wazuh-ip-block.ps1 -Unblock <ip>`.

- **The most recent block decides.** A new timed block replaces the task; a block without a
  timeout deletes it.
- **Missed run:** if the machine is off or asleep at the expiry time, the task runs as soon as
  possible afterwards (`StartWhenAvailable`).

### 8.3 Reboot

The task `\Wazuh\IP block - clear at startup` runs `wazuh-ip-block.ps1 -BootCleanup` at every
start. It removes **all** rules in group `Wazuh active response` and all expiry tasks.

- **When it's created:** on the first block.
- **If it can't be registered:** a `WARNING` is logged, and blocks then survive a reboot.

---

## 9. Logging

Everything goes to the standard Wazuh active-response log, which the agent forwards to the
manager:

```
C:\Program Files (x86)\ossec-agent\active-response\active-responses.log
```

```
2026/10/18 03:55:18 active-response/bin/wazuh-ip-block.cmd: Manual mode (API): add 203.0.113.41 for 3600s
2026/10/18 03:55:18 active-response/bin/wazuh-ip-block.cmd: Firewall in use: Windows Defender Firewall
2026/10/18 03:55:18 active-response/bin/wazuh-ip-block.cmd: ADD requested: IP=203.0.113.41
2026/10/18 03:55:18 active-response/bin/wazuh-ip-block.cmd: Timer: 203.0.113.41 will be unblocked in 3600s
2026/10/18 03:55:18 active-response/bin/wazuh-ip-block.cmd: SUCCESS: IP blocked: 203.0.113.41 firewall=Windows Defender Firewall for 3600s
2026/10/18 03:55:54 active-response/bin/wazuh-ip-block.cmd: Native AR mode: add 203.0.113.22 (rule 60122)
2026/10/18 03:55:27 active-response/bin/wazuh-ip-block.cmd: Startup cleanup: removed 4 rule(s) and 1 expiry task(s)
```

- **Content:** only the mode, origin, rule ID, action and address are logged, never the whole
  alert.
- **Line types:** `SUCCESS`, `DELETE done`, `REFUSED`, `ERROR` and `WARNING` are the lines to
  alert on.
- **Debug output:** set `$DebugLog = $true` at the top of the `.ps1` for firewall check details.

---

## 10. Files, rules, tasks and settings

| Item | Purpose |
|---|---|
| `active-response\bin\wazuh-ip-block.cmd` / `.ps1` | the script |
| `active-response\active-responses.log` | log |
| `wazuh-ip-block.never-block` (agent folder) | local never-block list (optional) |
| `shared\wazuh-ip-block.never-block` | central never-block list (optional) |
| firewall group `Wazuh active response` | all block rules |
| task folder `\Wazuh\` | startup cleanup task and expiry tasks |
| mutex `Global\WazuhIPBlock` | serializes runs |

Settings at the top of `wazuh-ip-block.ps1`:

| Setting | Default | Meaning |
|---|---|---|
| `$DebugLog` | `$false` | `$true` logs firewall check details |
| `$LockWait` | `60` | seconds to wait for another run before giving up |
| `$MaxTimeout` | `31536000` | longest accepted manual timeout (one year) |
| `$RuleGroup`, `$RulePrefix` | `Wazuh active response`, `WazuhIPBlock` | names of the rules |
| `$TaskPath` | `\Wazuh\` | folder of the scheduled tasks |

---

## 11. Exit codes

| Code | Meaning |
|---|---|
| `0` | done: blocked or unblocked, already the case, or `wazuh-execd` answered `abort` |
| `1` | refused (special address or never-block list), invalid input, firewall not usable for a block, the lock wasn't free within `$LockWait`, or a change failed or couldn't be confirmed (the log says which) |

---

## 12. Checking blocks by hand

```powershell
Get-NetFirewallRule -Group 'Wazuh active response' |
  Select-Object Name, Direction, Action, Enabled,
    @{n='RemoteAddress'; e={ ($_ | Get-NetFirewallAddressFilter).RemoteAddress }}
Get-ScheduledTask -TaskPath '\Wazuh\' | Select-Object TaskName, State
Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled, AllowLocalFirewallRules
```

---

## 13. Testing done

**Environment:** PowerShell 7.4 on Linux, with **mocked** Windows cmdlets: firewall rules and
profiles, the firewall service, network addresses/routes/DNS, and scheduled tasks. The mocks kept
their state in a file, and the real script ran unchanged against them.

**Address handling:** the same checks as for the Linux script, with identical results:
- 39 valid and invalid spellings, including the strictness rules (no `1.2.3`, `0x7f.0.0.1`,
  `%12`, leading zeros);
- IPv4/IPv6 CIDR matching;
- refusal of the manager, gateway, own address, DNS server, list entries and special addresses.

**Firewall behaviour (mocked):**
- block, and repeat block with **no** firewall calls;
- IPv6 spelling variants;
- replacement of a disabled rule;
- rollback when the outbound rule fails;
- refusal when the service is stopped, every profile is off, or Group Policy ignores local rules;
- a warning for a single profile that's off;
- unblock while the service is stopped.

**Expiry and reboot (mocked):**
- timeout validation;
- expiry tasks: the action, the trigger, SYSTEM principal; replaced by a newer block, cancelled
  by a block without timeout and by unblock; the `-Unblock` run itself;
- startup cleanup (removes rules and expiry tasks, keeps itself).

**Protocol and concurrency:**
- `check_keys` with a fake `wazuh-execd`: `abort` / `continue`; no handshake for manual calls
  or unblocks; no other stdout output;
- the native `data.win.eventdata.ipAddress` field;
- invalid JSON and invalid operations;
- 6 parallel runs serialized by the mutex.

**Not tested:** real Windows, Windows PowerShell 5.1, the real NetSecurity and ScheduledTasks
cmdlets, a real `wazuh-execd`. Do one block/unblock (with and without a timeout) and one reboot
on a real agent before relying on it.

---

## 14. Known gaps and limitations

**Coverage**
- **Forwarded and virtual-network traffic isn't blocked.** Traffic routed by the host (RRAS/ICS)
  and traffic to Hyper-V VMs, WSL 2, or Docker / Windows containers through their own virtual
  switches or NAT isn't filtered by host firewall rules.
- **Open connections.** The script relies on Windows re-checking existing connections when rules
  change; this is untested here. Applications may keep their sockets open until their own
  timeouts, even though traffic is dropped. Unlike on Linux, there's no equivalent of
  `conntrack -D`.
- **Third-party firewalls.** If another product disabled Windows Defender Firewall, the script
  refuses to block ("turned off for every profile"); it doesn't drive other firewalls.
- **Profiles that are off.** The block doesn't apply on networks whose profile is turned off
  (a `WARNING` is logged).
- **One address per call.** Networks (CIDR) can't be blocked, only listed as never-block.
- **The never-block list is built at block time.** A manager host name that can't be resolved at
  that moment isn't protected for that block (a `WARNING` is logged).

**Lifetime of blocks**
- **Native and manual blocks share the same two rules.** Wazuh's timeout `delete` also removes a
  manual block of the same address, and vice versa.
- **Startup task.** If it can't be registered, blocks survive a reboot.
- **Pending Wazuh timeouts at reboot.** At reboot, Wazuh forgets its pending timeout
  unblocks; the startup task removes those blocks.

**Environment**
- **Windows 7 / Server 2008 R2 aren't supported** (no NetSecurity module).
- **`AllSigned` execution policy** from Group Policy overrides `Bypass`: sign the script.
- **Log rotation.** Make sure `active-responses.log` is rotated; the script only appends.

**Untested parts**
- See section 13: real Windows, PowerShell 5.1, the real cmdlets and `wazuh-execd`.

---

## 15. Removing the script

```powershell
Get-NetFirewallRule -Group 'Wazuh active response' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Get-ScheduledTask -TaskPath '\Wazuh\' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
Remove-Item 'C:\Program Files (x86)\ossec-agent\active-response\bin\wazuh-ip-block.cmd',
            'C:\Program Files (x86)\ossec-agent\active-response\bin\wazuh-ip-block.ps1'
```

Then remove the `<command>` and `<active-response>` blocks from the manager's `ossec.conf`.
If you used ar-sync, also remove the two `.move` files from the manager's group folder.
