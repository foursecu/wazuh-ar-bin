# wazuh-ip-block.sh

A Wazuh active-response script for Linux agents. It blocks or unblocks one IPv4 or IPv6
address in whichever firewall the agent actually runs (firewalld, ufw, iptables or nftables).
The block behaves the same on all of them.

It works in two ways:
- triggered by **Wazuh rules** (native active response, with Wazuh's timeouts), or
- called **manually through the Wazuh API**, with an optional expiry.

It's the Linux counterpart of `wazuh-ip-block.ps1`.

---

## Contents

1. [What a block does](#1-what-a-block-does)
2. [Requirements](#2-requirements)
3. [Installation](#3-installation)
4. [Usage](#4-usage)
5. [Safety: addresses that are never blocked](#5-safety-addresses-that-are-never-blocked)
6. [Firewall support](#6-firewall-support)
7. [Unblocking](#7-unblocking)
8. [Logging](#8-logging)
9. [Files and state](#9-files-and-state)
10. [Exit codes](#10-exit-codes)
11. [Checking blocks by hand](#11-checking-blocks-by-hand)
12. [Testing done](#12-testing-done)
13. [Known gaps and limitations](#13-known-gaps-and-limitations)
14. [Removing the script](#14-removing-the-script)

---

## 1. What a block does

Whatever firewall is in use, a block is:

| Property | Meaning |
|---|---|
| **Both directions** | Traffic from the address is dropped, and so is traffic from the agent to it. |
| **Forwarded traffic too** | Traffic the agent routes or forwards, e.g. to **Docker containers** on published ports, is dropped as well. |
| **Immediate** | Connections that are already open stop working at once. |
| **Runtime only** | A reboot clears every block. This matches how Wazuh handles timeouts. |
| **Repeatable** | Blocking an address that's already blocked only adds what's missing. The address is never briefly unblocked. |
| **Checked** | Every change is read back from the firewall. A half-applied change is rolled back. |

Before blocking, the script refuses special addresses and anything on the never-block list
(section 5). Unblocking is always allowed for any valid address.

---

## 2. Requirements

- **System:** Linux, run as **root**. This is the case when `wazuh-execd` runs it.
- **Shell:** POSIX `sh`. Tested with `dash`; `bash` and busybox `sh` also work.
- **Required tools:** `sed`, `grep`, `tr`, `head`, `cut`, `id`, `date`. The script checks for them at start.
- **A firewall tool:** one of `firewall-cmd` (running), `ufw` (active), `iptables`/`ip6tables` or `nft`.
- **Optional tools**, used when installed:

| Tool | Used for | Without it |
|---|---|---|
| `jq` | reading the Wazuh message | a built-in parser is used (section 4.4) |
| `conntrack` (package `conntrack` / `conntrack-tools`) | clearing the address's tracked connections | open connections are still cut by the drop rules; the kernel's state just times out on its own |
| `ip` (iproute2) | finding the agent's own addresses and gateways for the never-block list | those addresses aren't protected |
| `getent` | resolving a manager configured as a host name | a manager given as a host name isn't protected (a warning is logged) |
| `timeout` | limiting the wait for `wazuh-execd`'s reply in the handshake (section 4.3) to 30 s | the script waits until execd answers |
| `setsid` | starting expiry timers fully detached | `nohup` is used |
| `find` | spotting a stale lock that has no pid | such a lock is never treated as stale |

`date +%s` (GNU coreutils or busybox) is needed for manual blocks with a timeout.

---

## 3. Installation

### 3.1 On each agent

```sh
install -o root -g wazuh -m 750 wazuh-ip-block.sh /var/ossec/active-response/bin/
```

**Central distribution with ar-sync:** copy the script to the manager as
`/var/ossec/etc/shared/<group>/wazuh-ip-block.sh.move`. The ar-sync mover installs it on every
Linux agent of that group (see `../README.md`).

### 3.2 Rule-triggered blocks (optional)

On the **manager**, in `/var/ossec/etc/ossec.conf`:

```xml
<command>
  <name>wazuh-ip-block</name>
  <executable>wazuh-ip-block.sh</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <command>wazuh-ip-block</command>
  <location>local</location>
  <rules_id>5763</rules_id>   <!-- e.g. sshd brute force -->
  <timeout>600</timeout>       <!-- seconds; Wazuh sends the unblock -->
</active-response>
```

**Longer blocks for repeat offenders:** add `<repeated_offenders>10,30,60</repeated_offenders>`
(minutes) to the agent's `<active-response>` section. This works because the script does the
handshake (section 4.3).

Manual blocks through the API (section 4.2) need no manager configuration.

### 3.3 Never-block list (recommended)

See section 5. At minimum, list your admin and jump-host networks. To manage the list
centrally, put `wazuh-ip-block.never-block` in the manager's group folder.

---

## 4. Usage

### 4.1 Rule-triggered (native mode)

Wazuh sends `"command": "add"` with the alert. The address comes from
`parameters.alert.data.srcip`. After the configured `<timeout>`, Wazuh sends
`"command": "delete"` for the same alert, which unblocks it.

### 4.2 Manual, through the Wazuh API (manual mode)

The operation and address go in `arguments`, which reach the script as `extra_args`:

```
PUT /active-response?agents_list=001,002
{ "command": "!wazuh-ip-block.sh", "arguments": ["block", "203.0.113.7"] }

PUT /active-response?agents_list=001,002
{ "command": "!wazuh-ip-block.sh", "arguments": ["block", "203.0.113.7", "3600"] }

PUT /active-response?agents_list=001,002
{ "command": "!wazuh-ip-block.sh", "arguments": ["unblock", "203.0.113.7"] }
```

| `arguments` | Effect |
|---|---|
| `["block", "<ip>"]` (or `add`) | Block until unblocked or rebooted. Cancels a pending timeout for that address. |
| `["block", "<ip>", "<seconds>"]` | Block, and unblock automatically after `<seconds>` (1 to 31536000, no leading zeros). |
| `["unblock", "<ip>"]` (or `delete`) | Unblock, and cancel any pending timeout. |

- **Case:** the operation names are case-insensitive.
- **Address formats:** an IPv6 address may be written in any form. Uppercase, a fully written-out form, and an IPv4-mapped form (`::ffff:a.b.c.d`) all refer to the same address.
- **Network masks:** a network mask (`/24`) is rejected. Only single addresses are blocked.

**How the timeout works:**
- A detached `sleep` process unblocks the address when the time is up.
- The **most recent block decides**. A later block of the same address replaces the pending timeout; a block without a timeout keeps the address blocked.
- An unblock cancels the timeout.

### 4.3 The handshake with wazuh-execd (`check_keys`)

**When it happens:** for a rule-triggered `add`.

**What it does:**
1. The script sends the address to `wazuh-execd` on stdout as `check_keys`.
2. If execd replies `abort`, meaning the address already has a pending timed block, the script exits 0 without touching the firewall.

**Why it matters:** repeated alerts don't pile up blocks, and `repeated_offenders` works.

**When it's skipped:** for manual calls (execd doesn't track them), for unblocks, and when run from a terminal. With `timeout` installed, the wait for a reply is limited to 30 s.

### 4.4 How the message is read

- **With `jq`** (when it's installed and can parse the message): exact fields are read: `command`, `origin.module`, `parameters.extra_args[0..2]`, `parameters.alert.data.srcip` and `parameters.alert.rule.id`.
- **Without `jq`:** a built-in parser reads the first top-level `command` and the `extra_args` array, and prefers `srcip` inside the alert's `data` object.
  - Quoted text inside log strings (e.g. `\"srcip\"` in `full_log`) doesn't match.
  - Whatever is read still has to pass the strict address check, so a misread fails safely.

### 4.5 Manual test on an agent

```sh
echo '{"command":"add","parameters":{"extra_args":["block","203.0.113.7","60"]}}' \
  | sudo /var/ossec/active-response/bin/wazuh-ip-block.sh; echo "rc=$?"
tail /var/ossec/logs/active-responses.log
```

---

## 5. Safety: addresses that are never blocked

A **block** is refused with exit code 1 and a `REFUSED to block ...` log line if the address
falls into either group below. An **unblock** is always allowed, so a mistaken block can be
removed.

### 5.1 Special addresses (in any spelling)

| IPv4 | IPv6 |
|---|---|
| `0.0.0.0/8` ("this network") | `::/96`: `::`, loopback `::1` and the obsolete IPv4-compatible form |
| `127.0.0.0/8` (loopback) | `fe80::/10` (link-local) |
| `169.254.0.0/16` (link-local, **includes cloud metadata 169.254.169.254**) | `ff00::/8` (multicast) |
| `224.0.0.0/4` (multicast) | |
| `240.0.0.0/4` (reserved, including `255.255.255.255`) | |

IPv6 addresses are written out in full before the check, so `0:0:0:0:0:0:0:1` and `0::1` are
caught as loopback. IPv4-mapped addresses (`::ffff:7f00:1`) are checked as IPv4.

### 5.2 The never-block list

Built from these sources on every block:

| Source | Details |
|---|---|
| **Wazuh manager** | every `<address>` in `<client><server>` of the agent's `ossec.conf`. Host names are resolved, so all their IPv4 and IPv6 addresses are protected. |
| **The agent itself** | its own addresses (`ip addr`), default gateways (`ip route`), DNS servers (`/etc/resolv.conf`) |
| **Local list** | `/var/ossec/etc/wazuh-ip-block.never-block` |
| **Central list** | `/var/ossec/etc/shared/wazuh-ip-block.never-block`. Put the file in the manager's group folder (e.g. `/var/ossec/etc/shared/AS/`) and Wazuh copies it to every agent in the group. |

List file format: one IPv4/IPv6 address or CIDR range per line, `#` comments allowed:

```
# admin networks
10.20.0.0/16        # jump hosts
192.0.2.15
2001:db8:aaaa::/48
```

Example log line:
`REFUSED to block 10.20.5.5: on the never-block list as 10.20.0.0/16 (/var/ossec/etc/wazuh-ip-block.never-block)`

---

## 6. Firewall support

### 6.1 Detection order

The first firewall that is installed **and** actually working wins:

| # | Firewall | Condition |
|---|---|---|
| 1 | firewalld | `firewall-cmd --state` says `running` |
| 2 | ufw | `ufw status` says `Status: active` |
| 3 | iptables / ip6tables | answers a read-only probe. If it's the **nf_tables variant** and `nft` works, the native nft backend is used instead. |
| 4 | nftables | `nft list tables` works |

### 6.2 What each one gets

Each block has two parts:
- **Host rules** in the detected firewall.
- **Guard rules.** They drop the address before connection tracking, Docker's port forwarding and the "established connection" accepts that firewalld and ufw put first. This is what makes the behaviour in section 1 the same everywhere.

| Firewall | Host rules | Guard rules |
|---|---|---|
| firewalld | runtime rich rule `source address=IP drop` in the **default zone and every active zone** | nft table `inet wazuh_ar` (`prerouting` at raw priority + `output`); iptables `raw` if `nft` isn't available |
| ufw | none. ufw rules are permanent, so they're avoided. | iptables `raw`: `PREROUTING -s/-d`, `OUTPUT -d` |
| iptables | `INPUT -s IP -j DROP`, `OUTPUT -d IP -j DROP` | iptables `raw`: `PREROUTING -s/-d`, `OUTPUT -d` |
| nftables | sets `blocked4`/`blocked6` in table `inet wazuh_ar`, used by its `input`, `output` and `prerouting` chains | the same table |

**Fallback** when the iptables `raw` table isn't available:
- The guard uses `DOCKER-USER` (or `FORWARD`) `-s/-d` plus `filter OUTPUT -d`.
- On **ufw**, the old **permanent** `ufw prepend deny from IP` / `deny out to IP` rules are used, and a `WARNING` is logged. On ufw older than 0.36 (no `prepend`), the deny is inserted before the first rule of the same address family.

After every block, `conntrack -D` clears the address's tracked connections when `conntrack` is
installed.

---

## 7. Unblocking

An unblock removes the address from **every** firewall it finds, not only the one detected now.
A block made while another firewall was in use is cleaned up too, e.g. iptables while firewalld
was stopped, or ufw before it was disabled.

- **firewalld** (if running): the rule is removed from every zone that has it, including inactive zones.
- **ufw** (if installed, even inactive): `ufw delete` of both deny rules.
- **iptables / ip6tables:** host rules, plus guard rules in `raw`, `DOCKER-USER`, `FORWARD` and `OUTPUT`.
- **nft:** set entries in `inet wazuh_ar`, then read back to confirm they're gone.
- **Timers:** any pending timeout for the address is cancelled.

An unblock still runs when no firewall is detected; it cleans whatever it can find.

---

## 8. Logging

All output goes to the standard Wazuh active-response log, which the agent forwards to the
manager:

```
/var/ossec/logs/active-responses.log
```

The format matches the built-in scripts:

```
2026/10/17 20:41:33 active-response/bin/wazuh-ip-block.sh: Manual mode (API): add 203.0.113.31 for 5s
2026/10/17 20:41:33 active-response/bin/wazuh-ip-block.sh: Firewall in use: nft
2026/10/17 20:41:33 active-response/bin/wazuh-ip-block.sh: ADD requested: IP=203.0.113.31 firewall=nft
2026/10/17 20:41:33 active-response/bin/wazuh-ip-block.sh: Timer: 203.0.113.31 will be unblocked in 5s
2026/10/17 20:41:33 active-response/bin/wazuh-ip-block.sh: SUCCESS: IP blocked: 203.0.113.31 firewall=nft for 5s
2026/10/17 20:41:33 active-response/bin/wazuh-ip-block.sh: Native AR mode: delete 203.0.113.30 (rule 5763)
2026/10/17 20:41:33 active-response/bin/wazuh-ip-block.sh: DELETE done: IP=203.0.113.30 (checked: iptables nft)
```

- **Content:** only the mode, origin, rule ID, action and address are logged, never the whole alert.
- **Line types:** `SUCCESS`, `DELETE done`, `REFUSED`, `ERROR` and `WARNING` are the lines to alert on.
- **Debug output:** to log firewall detection details too (tools not found, probe failures), set `DEBUG=1` at the top of the script.
- **Old log file:** earlier versions wrote to `active-response/bin/wazuh-ip-block.log`. That file is no longer used and can be deleted.

---

## 9. Files and state

| Path (under `/var/ossec`) | Purpose |
|---|---|
| `active-response/bin/wazuh-ip-block.sh` | the script |
| `logs/active-responses.log` | log (section 8) |
| `etc/wazuh-ip-block.never-block` | local never-block list (optional) |
| `etc/shared/wazuh-ip-block.never-block` | central never-block list, from the agent group (optional) |
| `var/run/wazuh-ip-block.lock/` | lock directory while a run is active; a stale one (dead pid) is removed automatically |
| `var/run/wazuh-ip-block.timers/<ip>` | one file per address with a pending manual timeout (`:` in IPv6 written as `_`) |
| nft table `inet wazuh_ar` | the script's own nftables table (sets `blocked4`, `blocked6`) |

Settings at the top of the script:

| Setting | Default | Meaning |
|---|---|---|
| `DEBUG` | `0` | `1` logs firewall detection details |
| `LOCK_WAIT` | `60` | seconds to wait for another run before giving up |
| `MAX_TIMEOUT` | `31536000` | longest accepted manual timeout (one year) |

`PATH` is fixed inside the script (`/usr/local/sbin:...:/bin`), because it runs as root.

---

## 10. Exit codes

| Code | Meaning |
|---|---|
| `0` | done: blocked or unblocked, already the case, or `wazuh-execd` answered `abort` |
| `1` | refused (special address or never-block list), invalid input, not root, no usable firewall for a block, the lock wasn't free within `LOCK_WAIT`, or a firewall change failed or couldn't be confirmed (the log says which) |

---

## 11. Checking blocks by hand

```sh
nft list table inet wazuh_ar                    # nft backend and nft guard rules
iptables -t raw -S; ip6tables -t raw -S         # guard rules (ufw, iptables)
iptables -S | grep DROP                         # iptables host rules
firewall-cmd --list-all-zones | grep 'source address'   # firewalld
ufw status numbered                             # ufw (fallback only)
ls /var/ossec/var/run/wazuh-ip-block.timers/    # pending manual timeouts
```

**On ufw systems, blocks don't appear in `ufw status`.** They're in `iptables -t raw -S`, or in
`nft list table inet wazuh_ar` when nft rules are used instead.

---

## 12. Testing done

**Environment:** throwaway Linux network namespaces with iptables 1.8 (nf_tables variant) and
nft. The script was run under `dash`, as root.

**Tested with real iptables / nft:**
- IPv4 and IPv6 block and unblock.
- Repeat blocks: no delete calls, so no gap.
- Forwarding test: an "attacker" namespace, a Docker-style "container" behind a routing
  namespace with Docker-like accept rules. After a block, new and open TCP connections were cut in
  both directions; after an unblock, everything was reachable again with no leftover rules.
- The fallback with no `raw` table (`DOCKER-USER`).
- Detection preferring nft for the nf_tables iptables variant.
- Cleanup across firewall changes, e.g. blocked with iptables and unblocked with nft as the backend.

**Address handling:** normalisation and special-address checks for many valid and invalid
spellings; IPv4 and IPv6 CIDR matching; refusal of the manager (IP, host name resolving to IPv4
and IPv6), gateway, own address and list entries.

**Tested with stand-ins** (simplified fake tools; the real ones aren't installed in the test
environment):
- **firewalld:** per-zone rules, rollback, and removal from inactive zones.
- **ufw:** IPv4/IPv6 list placement, with and without `prepend`.
- **conntrack:** calls and logging.
- **wazuh-execd:** the `check_keys` handshake (`abort` / `continue`); no handshake for manual
  calls or unblocks.

**Other checks:**
- Both message parsers (with `jq`, and the fallback), including misleading `srcip` text inside log strings.
- Timeout validation, and expiry timers: expiry, a later block overriding a timeout, unblock cancelling it.
- 8 parallel runs serialized by the lock; stale-lock recovery.
- The caller's `PATH` being ignored.

**Not tested:** real firewalld, real ufw, a real Docker host, a real `wazuh-execd`.
Do one block/unblock on each kind of agent before relying on it.

---

## 13. Known gaps and limitations

**Lifetime of blocks**
- **Reboot clears all blocks**, by design. That includes manual blocks without a timeout and
  pending timers. If manual blocks must last, re-send them after a reboot (e.g. from the trigger
  cron).
- **Reloads can clear blocks early.** Debian's `nftables.service` reload runs `flush ruleset`,
  which removes `inet wazuh_ar`. `firewall-cmd --reload` removes the rich rules and, when nft
  isn't available, the iptables guard rules too.
- **Native and manual blocks share the same rules.** If an address is blocked by a rule and also
  manually, Wazuh's timeout `delete` for the rule-triggered block also removes the manual one.
  The reverse applies too: a manual unblock removes a rule-triggered block early.

**Coverage**
- **One address per call.** Networks (CIDR) can't be blocked, only listed as never-block.
- **firewalld zones that become active later** (e.g. a VPN interface coming up) don't get the
  rich rule. The guard rules still cover them whenever nft or the iptables `raw` table is
  available, which is the normal case.
- **The never-block list is built at block time.** A manager address that can't be resolved at
  that moment isn't protected for that block (a `WARNING` is logged).

**Side effects**
- **Unblock removes look-alike rules.** An admin's own rule with exactly the same shape
  (e.g. `INPUT -s IP -j DROP`) is removed too.
- **Persistent ufw rules in the fallback only.** Without an iptables `raw` table and without nft,
  ufw blocks are permanent and survive a reboot. Unblock still removes them.

**Security**
- **The central never-block file can be edited locally.** On the agent, the `wazuh` group can
  change `etc/shared/wazuh-ip-block.never-block`. The worst this can do is exempt addresses
  from blocking.

**Runtime limits**
- **Lock.** During very large alert bursts, a run that waits longer than `LOCK_WAIT` gives up
  with an `ERROR`.
- **Handshake without `timeout`.** The script waits for `wazuh-execd`'s reply with no time limit.
- **Log rotation.** Make sure `active-responses.log` is rotated on your systems; the script only
  appends to it.

**Untested parts**
- Real firewalld, real ufw, a real Docker host and a real `wazuh-execd` (see section 12).
  ufw's `status` output format for IPv6 addresses is assumed. If it differs, the ufw-fallback
  check fails safely: the block reports an error and is rolled back.

---

## 14. Removing the script

1. Unblock every address you blocked, or reboot the agent.
2. Delete leftovers:

```sh
nft delete table inet wazuh_ar 2>/dev/null
rm -rf /var/ossec/var/run/wazuh-ip-block.lock /var/ossec/var/run/wazuh-ip-block.timers
rm -f /var/ossec/active-response/bin/wazuh-ip-block.sh /var/ossec/active-response/bin/wazuh-ip-block.log
```

3. Remove the `<command>` and `<active-response>` blocks from the manager's `ossec.conf`.
   If you distributed the script with ar-sync, also remove
   `/var/ossec/etc/shared/<group>/wazuh-ip-block.sh.move`. ar-sync doesn't delete files it
   installed.
