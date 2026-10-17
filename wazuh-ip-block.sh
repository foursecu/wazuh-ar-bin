#!/bin/sh
# wazuh-ip-block.sh - Linux counterpart of wazuh-ip-block.ps1
#
# Reads one line of Wazuh active-response JSON from STDIN and blocks or
# unblocks an IP address. Full documentation: wazuh-ip-block.md
#
#   Manual API mode : parameters.extra_args = ["block"|"add"|"unblock"|"delete", "<ip>" [, "<seconds>"]]
#                     (an optional timeout makes a manual block expire on its own)
#   Native AR mode  : command = add|delete, parameters.alert.data.srcip
#
# Portable POSIX sh. It needs sed, grep, tr, head, cut, id and date, plus one
# firewall tool. It uses jq, conntrack, ip, getent, setsid and timeout when
# they are installed.
#
# The script first finds out WHICH firewall this machine is really using (a
# tool that is installed but not running or not active is skipped), then uses
# the matching commands. Order of detection:
#   1. firewalld  - "firewall-cmd --state" says running   -> runtime rich rule in every active zone
#   2. ufw        - "ufw status" says Status: active      -> guard only (see below)
#   3. iptables   - iptables/ip6tables answers a probe    -> INPUT + OUTPUT DROP
#                   (the nf_tables variant goes to 4 when nft works)
#   4. nftables   - nft answers a probe                   -> own table "inet wazuh_ar"
# Every block also adds a guard (see section 4) and clears the address's
# connection tracking, so whatever the firewall, a block is:
#   - runtime only (a reboot clears it, like Wazuh's own timeouts),
#   - in both directions, for this host and for forwarded traffic (Docker),
#   - effective at once, for connections that are already open too.
# Unblock removes the address from every firewall it finds, not only the one
# detected now, so a block made while another firewall was in use is removed too.
# Before it touches anything it checks that every command it needs exists and
# that it runs as root. After every change it reads the firewall back to
# confirm the result, and logs what the tool said when something goes wrong.
# Runs are serialized by a lock; a repeated block only adds what is missing.
#
# A block is refused (unblock is always allowed) when the address is:
#   - special: unspecified, loopback, link-local, multicast, broadcast or
#     reserved, in any spelling (IPv6 is compared in its full form)
#   - on the never-block list:
#       * the Wazuh manager address(es) from ossec.conf <client><server><address>
#         (host names are resolved with getent)
#       * this machine's own addresses, default gateways and DNS servers
#       * entries (IP or CIDR, one per line, # comments) in
#           <wazuh>/etc/wazuh-ip-block.never-block           (local)
#           <wazuh>/etc/shared/wazuh-ip-block.never-block    (from the agent group)


#PUT /active-response?agents_list=???
#{
#  "command": "!wazuh-ip-block.sh",
#  "arguments": ["block", "1.1.1.1"]
#}

#PUT /active-response?agents_list=???
#{
#  "command": "!wazuh-ip-block.sh",
#  "arguments": ["block", "1.1.1.1", "3600"]
#}

#PUT /active-response?agents_list=???
#{
#  "command": "!wazuh-ip-block.sh",
#  "arguments": ["unblock", "1.1.1.1"]
#}


# Set to 1 to also log firewall detection details.
DEBUG=0

# Seconds to wait for another run to finish before giving up.
LOCK_WAIT=60

# Longest accepted timeout for a manual block (one year).
MAX_TIMEOUT=31536000

# A fixed PATH: this script runs as root and must not pick up tools from the
# environment it was started with.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

SCRIPT_NAME=$(basename "$0")
SCRIPT_DIR=$(cd "$(dirname "$0")" 2>/dev/null && pwd) || SCRIPT_DIR=/var/ossec/active-response/bin
SELF="$SCRIPT_DIR/$SCRIPT_NAME"
WAZUH_HOME=$(cd "$SCRIPT_DIR/../.." 2>/dev/null && pwd) || WAZUH_HOME=/var/ossec
[ -f "$WAZUH_HOME/etc/ossec.conf" ] || WAZUH_HOME=/var/ossec
# the log every active response writes to; the agent forwards it to the manager
LOG_FILE="$WAZUH_HOME/logs/active-responses.log"
RUN_DIR="$WAZUH_HOME/var/run"
[ -d "$RUN_DIR" ] || RUN_DIR=/var/run
LOCK_DIR="$RUN_DIR/wazuh-ip-block.lock"
TIMER_DIR="$RUN_DIR/wazuh-ip-block.timers"
NEVER_BLOCK_FILES="$WAZUH_HOME/etc/wazuh-ip-block.never-block $WAZUH_HOME/etc/shared/wazuh-ip-block.never-block"

log() {
    printf '%s active-response/bin/%s: %s\n' "$(date '+%Y/%m/%d %H:%M:%S' 2>/dev/null)" \
        "$SCRIPT_NAME" "$*" >> "$LOG_FILE" 2>/dev/null
    return 0
}

debug() {
    [ "$DEBUG" = 1 ] && log "$*"
    return 0
}

fail() {
    log "ERROR: $*"
    exit 1
}

have() {
    command -v "$1" >/dev/null 2>&1
}

first_line() {
    printf '%s\n' "$1" | head -n 1
}

# ---------------------------------------------------------------------------
# 1. Required commands exist, and we are root
# ---------------------------------------------------------------------------

for _cmd in sed grep tr head cut id date; do
    have "$_cmd" || fail "required command not found: $_cmd"
done

[ "$(id -u)" = "0" ] || fail "must run as root (uid $(id -u))"

# ---------------------------------------------------------------------------
# 2. Read the Wazuh message (one JSON line on STDIN)
# ---------------------------------------------------------------------------

IFS= read -r INPUT || true
[ -n "$INPUT" ] || fail "Empty input"

# first string value of key $1 in JSON text $2 (fallback parser, no jq)
json_value() {
    printf '%s\n' "$2" | grep -o "\"$1\" *: *\"[^\"]*\"" | head -n 1 | sed 's/.*: *"//; s/"$//'
}

# element $1 (1-based) of the extra_args array, quotes and spaces removed
extra_arg() {
    printf '%s\n' "$EXTRA_ARGS" | cut -d, -f"$1" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//; s/^"//; s/"$//'
}

# jq only when it works and can parse this message; else the fallback parser
if have jq && printf '%s\n' "$INPUT" | jq -e . >/dev/null 2>&1; then
    COMMAND=$(printf '%s\n' "$INPUT" | jq -r '.command // empty' 2>/dev/null)
    ORIGIN=$(printf '%s\n' "$INPUT" | jq -r '.origin.module // empty' 2>/dev/null)
    RULE_ID=$(printf '%s\n' "$INPUT" | jq -r '.parameters.alert.rule.id // empty' 2>/dev/null)
    ARG_OP=$(printf '%s\n' "$INPUT" | jq -r '.parameters.extra_args[0] // empty' 2>/dev/null)
    ARG_IP=$(printf '%s\n' "$INPUT" | jq -r '.parameters.extra_args[1] // empty' 2>/dev/null)
    ARG_TIMEOUT=$(printf '%s\n' "$INPUT" | jq -r '.parameters.extra_args[2] // empty' 2>/dev/null)
    ALERT_IP=$(printf '%s\n' "$INPUT" | jq -r '.parameters.alert.data.srcip // empty' 2>/dev/null)
else
    # top-level fields come before "parameters" in the messages Wazuh writes,
    # so the first match is the right one
    COMMAND=$(json_value command "$INPUT")
    ORIGIN=$(json_value module "$INPUT")
    RULE_ID=$(printf '%s\n' "$INPUT" | sed -n 's/.*"rule" *: *{[^}]*"id" *: *"\([0-9]*\)".*/\1/p' | head -n 1)
    EXTRA_ARGS=$(printf '%s\n' "$INPUT" | sed -n 's/.*"extra_args" *: *\[\([^]]*\)\].*/\1/p' | head -n 1)
    ARG_OP=$(extra_arg 1)
    ARG_IP=$(extra_arg 2)
    ARG_TIMEOUT=$(extra_arg 3)
    # prefer srcip inside the alert's "data" object, then any srcip
    _data=$(printf '%s\n' "$INPUT" | grep -o '"data" *: *{[^}]*' | head -n 1)
    ALERT_IP=$(json_value srcip "$_data")
    [ -n "$ALERT_IP" ] || ALERT_IP=$(json_value srcip "$INPUT")
fi
[ -n "$COMMAND" ] || fail "Missing command"

if [ -n "$ARG_OP" ] && [ -n "$ARG_IP" ]; then
    MODE=manual
    case $(printf '%s' "$ARG_OP" | tr '[:upper:]' '[:lower:]') in
        add|block)      OPERATION=add ;;
        delete|unblock) OPERATION=delete ;;
        *) fail "Invalid extra_args operation: $ARG_OP" ;;
    esac
    RAW_IP=$ARG_IP
    if [ -n "$ARG_TIMEOUT" ]; then
        [ "$OPERATION" = add ] || fail "A timeout is only valid for block: $ARG_TIMEOUT"
        case $ARG_TIMEOUT in
            ""|*[!0-9]*|0*) fail "Invalid timeout (whole seconds, 1-$MAX_TIMEOUT): $ARG_TIMEOUT" ;;
        esac
        [ "${#ARG_TIMEOUT}" -le 9 ] && [ "$ARG_TIMEOUT" -le "$MAX_TIMEOUT" ] ||
            fail "Invalid timeout (whole seconds, 1-$MAX_TIMEOUT): $ARG_TIMEOUT"
    fi
    log "Manual mode (${ORIGIN:-unknown origin}): $OPERATION $RAW_IP${ARG_TIMEOUT:+ for ${ARG_TIMEOUT}s}"
else
    MODE=native
    OPERATION=$(printf '%s' "$COMMAND" | tr '[:upper:]' '[:lower:]')
    RAW_IP=$ALERT_IP
    [ -n "$RAW_IP" ] || fail "Missing parameters.alert.data.srcip"
    log "Native AR mode: $OPERATION $RAW_IP (rule ${RULE_ID:-unknown})"
fi

case $OPERATION in
    add|delete) ;;
    *) fail "Unsupported command: $OPERATION" ;;
esac

# ---------------------------------------------------------------------------
# 3. Validate the IP (it can come from log data, so be strict)
# ---------------------------------------------------------------------------

valid_ipv4() {
    printf '%s\n' "$1" | grep -Eq '^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$' || return 1
    _oldifs=$IFS
    IFS=.
    set -f
    set -- $1
    set +f
    IFS=$_oldifs
    for _octet in "$@"; do
        [ "$_octet" -le 255 ] || return 1
    done
    return 0
}

ipv4_int() {
    _oldifs=$IFS
    IFS=.
    set -f
    set -- $1
    set +f
    IFS=$_oldifs
    echo $(( ($1 << 24) + ($2 << 16) + ($3 << 8) + $4 ))
}

count_groups() {
    [ -n "$1" ] || { echo 0; return; }
    _oldifs=$IFS
    IFS=:
    set -f
    set -- $1
    set +f
    IFS=$_oldifs
    echo $#
}

# Prints the full form (8 groups of 4 lowercase hex digits) of a lowercase
# IPv6 address, or fails if it is not a valid IPv6 address.
ipv6_expand() {
    _a=$1
    printf '%s\n' "$_a" | grep -Eq '^[0-9a-f:.]{2,45}$' || return 1
    case $_a in
        *:::*|*::*::*|:[!:]*|*[!:]:) return 1 ;;
    esac
    # a dotted IPv4 tail (e.g. ::ffff:1.2.3.4) becomes two hex groups
    case $_a in
        *.*)
            _v4=${_a##*:}
            valid_ipv4 "$_v4" || return 1
            _n=$(ipv4_int "$_v4")
            _a="${_a%:*}:$(printf '%x:%x' $((_n >> 16)) $((_n & 65535)))"
            ;;
    esac
    case $_a in
        *::*)
            _head=${_a%%::*}
            _tail=${_a#*::}
            _zeros=$((8 - $(count_groups "$_head") - $(count_groups "$_tail")))
            [ "$_zeros" -ge 1 ] || return 1
            _a=$_head
            while [ "$_zeros" -gt 0 ]; do
                _a="${_a:+$_a:}0"
                _zeros=$((_zeros - 1))
            done
            _a="$_a${_tail:+:$_tail}"
            ;;
    esac
    [ "$(count_groups "$_a")" -eq 8 ] || return 1
    _oldifs=$IFS
    IFS=:
    set -f
    set -- $_a
    set +f
    IFS=$_oldifs
    _full=""
    for _g in "$@"; do
        printf '%s\n' "$_g" | grep -Eq '^[0-9a-f]{1,4}$' || return 1
        _full="${_full:+$_full:}$(printf '%04x' $((0x$_g)))"
    done
    echo "$_full"
}

# Prints the RFC 5952 short form of a full IPv6 address, so every spelling of
# an address reaches the firewall the same way.
ipv6_compress() {
    _oldifs=$IFS
    IFS=:
    set -f
    set -- $1
    set +f
    IFS=$_oldifs
    # longest run of two or more zero groups (the first one on a tie)
    _i=0 _best=-1 _bestlen=0 _cur=0 _curlen=0
    for _g in "$@"; do
        if [ "$_g" = 0000 ]; then
            [ "$_curlen" -eq 0 ] && _cur=$_i
            _curlen=$((_curlen + 1))
            if [ "$_curlen" -gt "$_bestlen" ]; then
                _best=$_cur
                _bestlen=$_curlen
            fi
        else
            _curlen=0
        fi
        _i=$((_i + 1))
    done
    [ "$_bestlen" -ge 2 ] || _best=-1
    _out="" _i=0
    for _g in "$@"; do
        if [ "$_best" -ge 0 ] && [ "$_i" -ge "$_best" ] && [ "$_i" -lt $((_best + _bestlen)) ]; then
            [ "$_i" -eq "$_best" ] && _out="$_out::"
        else
            case $_out in
                ""|*:) ;;
                *) _out="$_out:" ;;
            esac
            _out="$_out$(printf '%x' $((0x$_g)))"
        fi
        _i=$((_i + 1))
    done
    echo "$_out"
}

# Prints "<family> <canonical address>" for a valid IPv4 or IPv6 address, or
# fails. An IPv4-mapped IPv6 address (::ffff:a.b.c.d in any spelling) is
# really an IPv4 client and is returned as IPv4.
normalize_ip() {
    _addr=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
    if valid_ipv4 "$_addr"; then
        echo "4 $_addr"
        return 0
    fi
    _full=$(ipv6_expand "$_addr") || return 1
    case $_full in
        0000:0000:0000:0000:0000:ffff:*)
            _hi=$((0x$(printf '%s' "$_full" | cut -d: -f7)))
            _lo=$((0x$(printf '%s' "$_full" | cut -d: -f8)))
            echo "4 $((_hi >> 8)).$((_hi & 255)).$((_lo >> 8)).$((_lo & 255))"
            return 0
            ;;
    esac
    echo "6 $(ipv6_compress "$_full")"
}

# Prints why a normalized address must never be blocked, or nothing.
special_reason() {
    if [ "$1" = 4 ]; then
        _first=${2%%.*}
        _second=${2#*.}
        _second=${_second%%.*}
        if [ "$_first" -eq 0 ]; then echo "'this network' address (0.0.0.0/8)"
        elif [ "$_first" -eq 127 ]; then echo "loopback address (127.0.0.0/8)"
        elif [ "$_first" -eq 169 ] && [ "$_second" -eq 254 ]; then
            echo "link-local address (169.254.0.0/16, includes cloud metadata services)"
        elif [ "$_first" -ge 224 ] && [ "$_first" -le 239 ]; then echo "multicast address (224.0.0.0/4)"
        elif [ "$_first" -ge 240 ]; then echo "reserved or broadcast address (240.0.0.0/4)"
        fi
        return 0
    fi
    _full=$(ipv6_expand "$2")
    case $_full in
        0000:0000:0000:0000:0000:0000:*)
            echo "unspecified, loopback or IPv4-compatible address (::/96)" ;;
        fe[89ab]?:*) echo "link-local address (fe80::/10)" ;;
        ff??:*)      echo "multicast address (ff00::/8)" ;;
    esac
}

# Succeeds if normalized address $2 (family $1) is inside entry $3 (IP or CIDR).
ip_matches() {
    _net=${3%%/*}
    _len=${3#"$_net"}
    _len=${_len#/}
    _norm=$(normalize_ip "$_net") || return 1
    [ "${_norm%% *}" = "$1" ] || return 1
    _net=${_norm#* }
    if [ "$1" = 4 ]; then _max=32; else _max=128; fi
    if [ -z "$_len" ]; then
        _len=$_max
    else
        case $_len in
            *[!0-9]*) return 1 ;;
        esac
        [ "$_len" -le "$_max" ] || return 1
    fi
    if [ "$1" = 4 ]; then
        _shift=$((32 - _len))
        [ $(( $(ipv4_int "$2") >> _shift )) -eq $(( $(ipv4_int "$_net") >> _shift )) ]
        return
    fi
    # IPv6: compare whole hex digits, then the remaining bits of the next digit
    _a=$(ipv6_expand "$2" | tr -d :)
    _b=$(ipv6_expand "$_net" | tr -d :)
    _nibbles=$((_len / 4))
    _bits=$((_len % 4))
    if [ "$_nibbles" -gt 0 ]; then
        [ "$(printf '%s' "$_a" | cut -c1-"$_nibbles")" = "$(printf '%s' "$_b" | cut -c1-"$_nibbles")" ] || return 1
    fi
    [ "$_bits" -eq 0 ] && return 0
    _pos=$((_nibbles + 1))
    _da=$((0x$(printf '%s' "$_a" | cut -c"$_pos")))
    _db=$((0x$(printf '%s' "$_b" | cut -c"$_pos")))
    [ $((_da >> (4 - _bits))) -eq $((_db >> (4 - _bits))) ]
}

# Prints "<source> <entry>" lines: every address or network never to block.
never_block_entries() {
    _conf="$WAZUH_HOME/etc/ossec.conf"
    if [ -r "$_conf" ]; then
        sed -n '/<client>/,/<\/client>/p' "$_conf" \
            | sed -n 's:.*<address>[[:space:]]*\([^<[:space:]]*\)[[:space:]]*</address>.*:\1:p' \
            | while read -r _mgr; do
                if normalize_ip "$_mgr" >/dev/null; then
                    echo "manager $_mgr"
                elif have getent; then
                    _ips=$(getent ahosts "$_mgr" 2>/dev/null | sed 's/[[:space:]].*//')
                    [ -n "$_ips" ] || log "WARNING: cannot resolve manager address $_mgr; it is not protected"
                    for _ip in $_ips; do echo "manager $_ip"; done
                else
                    log "WARNING: getent not found, manager address $_mgr is not protected"
                fi
            done
    else
        log "WARNING: cannot read $_conf; manager address is not protected"
    fi

    if have ip; then
        ip -o addr show 2>/dev/null \
            | sed -n 's/.* inet6\{0,1\} \([^ /]*\).*/local-address \1/p'
        { ip route show default; ip -6 route show default; } 2>/dev/null \
            | sed -n 's/.* via \([^ ]*\).*/gateway \1/p'
    fi

    if [ -r /etc/resolv.conf ]; then
        sed -n 's/^[[:space:]]*nameserver[[:space:]]\{1,\}\([^[:space:]#%]*\).*/dns-server \1/p' /etc/resolv.conf
    fi

    for _file in $NEVER_BLOCK_FILES; do
        [ -r "$_file" ] || continue
        sed 's/#.*//; s/^[[:space:]]*//; s/[[:space:]]*$//; /^$/d' "$_file" \
            | while read -r _entry; do echo "$_file $_entry"; done
    done
}

# Prints the first never-block entry that covers the normalized address.
never_block_hit() {
    never_block_entries | while read -r _src _entry; do
        _entry=${_entry%%%*}    # drop an IPv6 zone index (fe80::1%eth0)
        if ip_matches "$1" "$2" "$_entry"; then
            echo "$_entry ($_src)"
            break
        fi
    done
}

IP=$(printf '%s' "$RAW_IP" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
_norm=$(normalize_ip "$IP") || fail "Invalid IP address: $RAW_IP"
FAMILY=${_norm%% *}
IP=${_norm#* }

# Unblocking stays possible for every valid address, so a mistaken block can
# always be removed.
if [ "$OPERATION" = add ]; then
    _reason=$(special_reason "$FAMILY" "$IP")
    [ -z "$_reason" ] || fail "REFUSED to block $IP: $_reason"
    _hit=$(never_block_hit "$FAMILY" "$IP")
    [ -z "$_hit" ] || fail "REFUSED to block $IP: on the never-block list as $_hit"
fi

# Wazuh 4.2+ protocol for a rule-triggered "add": send the key (the address)
# and wait for "continue" or "abort". wazuh-execd answers "abort" while the
# address already has a pending timed block, so repeated alerts do not stack
# up blocks and repeated_offenders can lengthen the timeout. Manual API calls
# skip it: they are not tracked by execd.
check_keys() {
    printf '{"version":1,"origin":{"name":"%s","module":"active-response"},"command":"check_keys","parameters":{"keys":["%s"]}}\n' \
        "$SCRIPT_NAME" "$IP"
    if have timeout; then
        _reply=$(timeout 30 sh -c 'IFS= read -r _l && printf "%s" "$_l"')
    else
        IFS= read -r _reply || _reply=""
    fi
    if [ -z "$_reply" ]; then
        debug "no check_keys reply (not started by wazuh-execd?), continuing"
        return 0
    fi
    _answer=$(json_value command "$_reply")
    [ "$_answer" != abort ]
}

if [ "$MODE" = native ] && [ "$OPERATION" = add ] && [ "$COMMAND" = add ] && [ ! -t 0 ]; then
    check_keys || {
        log "execd says abort: $IP is already blocked by an active timed block"
        exit 0
    }
fi

# Serialize runs: alert bursts start many at once, and some firewall tools
# (ufw in particular) are not safe to run in parallel.
HAVE_LOCK=0
release_lock() {
    [ "$HAVE_LOCK" = 1 ] && rm -rf "$LOCK_DIR"
    HAVE_LOCK=0
}

# mkdir is atomic, so it works as a portable lock without flock
try_lock() {
    if mkdir "$LOCK_DIR" 2>/dev/null; then
        echo $$ > "$LOCK_DIR/pid"
        HAVE_LOCK=1
        return 0
    fi
    _pid=$(cat "$LOCK_DIR/pid" 2>/dev/null)
    if [ -n "$_pid" ]; then
        kill -0 "$_pid" 2>/dev/null && return 1
    elif [ -z "$(find "$LOCK_DIR" -maxdepth 0 -mmin +10 2>/dev/null)" ]; then
        # no pid yet: the owner may have just created the lock
        return 1
    fi
    log "Removing stale lock $LOCK_DIR"
    rm -rf "$LOCK_DIR"
    return 1
}

trap release_lock EXIT
trap 'exit 1' INT TERM HUP
_waited=0
until try_lock; do
    [ "$_waited" -ge "$LOCK_WAIT" ] && fail "another run still holds $LOCK_DIR after ${LOCK_WAIT}s"
    sleep 1
    _waited=$((_waited + 1))
done

# ---------------------------------------------------------------------------
# 4. Detect which firewall this machine is using
#    (the command must exist AND the firewall must be running / answer a probe)
# ---------------------------------------------------------------------------

IPT=""
IPT_W=""
BACKEND=""

detect_backend() {
    # 1) firewalld: installed AND running
    if have firewall-cmd; then
        _out=$(firewall-cmd --state 2>&1)
        if [ "$_out" = "running" ]; then
            BACKEND=firewalld
            return 0
        fi
        debug "firewall-cmd found but firewalld is not running ($(first_line "$_out"))"
    else
        debug "firewall-cmd not found"
    fi

    # 2) ufw: installed AND active
    if have ufw; then
        _out=$(LC_ALL=C ufw status 2>&1)
        case $_out in
            "Status: active"*)
                BACKEND=ufw
                return 0
                ;;
        esac
        debug "ufw found but it is not active ($(first_line "$_out"))"
    else
        debug "ufw not found"
    fi

    # 3) iptables / ip6tables: installed AND answers a read-only probe. The
    #    nf_tables variant only translates to nftables, so when nft itself
    #    works the native nft backend (one table, sets) is used instead.
    if [ "$FAMILY" = 6 ]; then _tool=ip6tables; else _tool=iptables; fi
    if have "$_tool"; then
        case $("$_tool" -V 2>/dev/null) in
            *nf_tables*)
                if nft_usable; then
                    debug "$_tool is the nf_tables variant, using nft directly"
                    BACKEND=nft
                    return 0
                fi
                ;;
        esac
        if "$_tool" -w -L -n >/dev/null 2>&1; then
            IPT=$_tool
            IPT_W="-w"
            BACKEND=iptables
            return 0
        fi
        _out=$("$_tool" -L -n 2>&1) && { IPT=$_tool; BACKEND=iptables; return 0; }
        debug "$_tool exists but its probe failed: $(first_line "$_out")"
    else
        debug "$_tool not found"
    fi

    # 4) nftables: installed AND answers a read-only probe
    if have nft; then
        _out=$(nft list tables 2>&1) && { BACKEND=nft; return 0; }
        debug "nft exists but its probe failed: $(first_line "$_out")"
    else
        debug "nft not found"
    fi
    return 1
}

# --- firewalld (runtime rich rule in every zone that gets traffic) ----------
# Each packet is handled by one zone: the zone its source address is bound
# to, else its interface's zone, else the default zone. A rule only in the
# default zone misses interfaces and sources bound to other zones (trusted,
# internal, ...), so the rule goes into every active zone plus the default
# zone. Rich rules come before a zone's target, so this works in "trusted" too.

fwd_rule() {
    if [ "$FAMILY" = 6 ]; then _fam=ipv6; else _fam=ipv4; fi
    printf 'rule family="%s" source address="%s" drop' "$_fam" "$IP"
}

# the default zone and every active zone, once each
fwd_zones() {
    _zones=""
    for _z in $({ firewall-cmd --get-default-zone; firewall-cmd --get-active-zones; } 2>/dev/null \
        | sed -n 's/^\([^[:space:]][^[:space:]]*\).*/\1/p'); do
        case " $_zones " in
            *" $_z "*) ;;
            *) _zones="$_zones $_z" ;;
        esac
    done
    echo $_zones
}

# zones (active or not) whose runtime rules contain the rich rule for $IP
fwd_rule_zones() {
    _all=$(firewall-cmd --list-all-zones 2>/dev/null) || return 1
    _rule=$(fwd_rule)
    _zone=""
    printf '%s\n' "$_all" | while IFS= read -r _line; do
        case $_line in
            [![:space:]]*)
                _zone=${_line%% *}
                ;;
            *"$_rule")
                # only whitespace before the rule: an exact match, not part of a longer rule
                case ${_line%"$_rule"} in
                    *[![:space:]]*) ;;
                    *) echo "$_zone" ;;
                esac
                ;;
        esac
    done
}

fwd_add() {
    _rule=$(fwd_rule)
    _zones=$(fwd_zones)
    if [ -z "$_zones" ]; then
        log "ERROR: firewalld reported no default or active zone"
        return 1
    fi
    for _z in $_zones; do
        _out=$(firewall-cmd --zone="$_z" --add-rich-rule="$_rule" 2>&1) || {
            log "ERROR firewall-cmd --zone=$_z --add-rich-rule failed: $(first_line "$_out")"
            fwd_remove
            return 1
        }
        firewall-cmd --zone="$_z" --query-rich-rule="$_rule" >/dev/null 2>&1 || {
            log "ERROR: rich rule for $IP not found in zone $_z after adding it"
            fwd_remove
            return 1
        }
    done
    log "firewalld: rich rule for $IP added in zone(s): $_zones"
    return 0
}

fwd_remove() {
    _rule=$(fwd_rule)
    _zones=$(fwd_rule_zones) || {
        _zones=$(firewall-cmd --get-default-zone 2>/dev/null)
        log "WARNING: firewall-cmd --list-all-zones failed, removing $IP from the default zone ($_zones) only"
    }
    [ -n "$_zones" ] || return 0
    _status=0
    for _z in $_zones; do
        _out=$(firewall-cmd --zone="$_z" --remove-rich-rule="$_rule" 2>&1) ||
            log "DELETE: firewall-cmd (zone $_z) said: $(first_line "$_out")"
        if firewall-cmd --zone="$_z" --query-rich-rule="$_rule" >/dev/null 2>&1; then
            log "ERROR: rich rule for $IP is still present in zone $_z after removal"
            _status=1
        fi
    done
    [ "$_status" -eq 0 ] && log "firewalld: rich rule for $IP removed from zone(s): $(echo $_zones)"
    return $_status
}

# --- ufw (deny from IP, deny out to IP) ---------------------------------------
# Only used when the guard cannot block on its own (see section 4): these
# rules are persistent. ufw keeps IPv4 and IPv6 rules in separate lists, and
# a deny only wins if it comes before any allow of its own family.

ufw_cmd() {
    LC_ALL=C ufw "$@"
}

ufw_remove_quiet() {
    ufw_cmd --force delete deny from "$IP" >/dev/null 2>&1
    ufw_cmd --force delete deny out to "$IP" >/dev/null 2>&1
    return 0
}

# how many "ufw status" DENY lines name exactly this address, for either family
ufw_deny_count() {
    _re=$(printf '%s' "$IP" | sed 's/[.]/\\./g')
    ufw_cmd status 2>/dev/null | grep -E "(^|[[:space:]])$_re([[:space:]]|\$)" | grep -c DENY
}

# number of the first rule of this address family in "ufw status numbered",
# or nothing when there is none; IPv6 rules show "(v6)" or an IPv6 address
ufw_first_pos() {
    ufw_cmd status numbered 2>/dev/null | while IFS= read -r _line; do
        case $_line in
            "["*"]"*) ;;
            *) continue ;;
        esac
        _num=${_line#"["}
        _num=$(echo ${_num%%"]"*})
        if printf '%s\n' "$_line" | grep -Eq '\(v6\)|[0-9A-Fa-f]*:[0-9A-Fa-f]*:'; then
            _fam=6
        else
            _fam=4
        fi
        if [ "$_fam" = "$FAMILY" ]; then
            echo "$_num"
            break
        fi
    done
}

# adds a rule ahead of every other rule of its address family
ufw_insert_first() {
    # ufw 0.36 and later
    _out=$(ufw_cmd prepend "$@" 2>&1) && return 0
    # older ufw: "insert 1" fails for IPv6 when rule 1 is an IPv4 rule, so
    # insert before the first rule of this family instead
    _pos=$(ufw_first_pos)
    if [ -n "$_pos" ]; then
        _out=$(ufw_cmd insert "$_pos" "$@" 2>&1) && return 0
    else
        # no rule of this family yet: appending makes it the first one
        _out=$(ufw_cmd "$@" 2>&1) && return 0
    fi
    return 1
}

ufw_add() {
    # already blocked: leave it, so there is no moment without the block
    [ "$(ufw_deny_count)" -ge 2 ] && return 0
    ufw_remove_quiet    # remove partial old copies first
    ufw_insert_first deny from "$IP" || {
        log "ERROR ufw deny from $IP failed: $(first_line "$_out")"
        return 1
    }
    ufw_insert_first deny out to "$IP" || {
        log "ERROR ufw deny out to $IP failed: $(first_line "$_out")"
        ufw_remove_quiet
        return 1
    }
    if [ "$(ufw_deny_count)" -lt 2 ]; then
        log "ERROR: DENY rules for $IP not found in 'ufw status' after adding them"
        ufw_remove_quiet
        return 1
    fi
    return 0
}

ufw_remove() {
    ufw_remove_quiet
    if [ "$(ufw_deny_count)" -gt 0 ]; then
        log "ERROR: a DENY rule for $IP is still in 'ufw status' after removal"
        return 1
    fi
    return 0
}

# --- iptables / ip6tables (INPUT + OUTPUT DROP) -------------------------------

ipt() {
    "$IPT" $IPT_W "$@"
}

ipt_remove_all() {
    _n=0
    while [ "$_n" -lt 50 ] && ipt -D INPUT -s "$IP" -j DROP >/dev/null 2>&1; do
        _n=$((_n + 1))
    done
    _n=0
    while [ "$_n" -lt 50 ] && ipt -D OUTPUT -d "$IP" -j DROP >/dev/null 2>&1; do
        _n=$((_n + 1))
    done
}

ipt_present() {
    ipt -C INPUT -s "$IP" -j DROP >/dev/null 2>&1 &&
        ipt -C OUTPUT -d "$IP" -j DROP >/dev/null 2>&1
}

ipt_leftover() {
    ipt -C INPUT -s "$IP" -j DROP >/dev/null 2>&1 ||
        ipt -C OUTPUT -d "$IP" -j DROP >/dev/null 2>&1
}

# adds only the rules that are missing, so a repeated block never opens a gap;
# on failure only the rules added by this run are rolled back
ipt_add() {
    _added=""
    for _r in INPUT:-s OUTPUT:-d; do
        ipt -C "${_r%%:*}" "${_r#*:}" "$IP" -j DROP >/dev/null 2>&1 && continue
        _out=$(ipt -I "${_r%%:*}" "${_r#*:}" "$IP" -j DROP 2>&1) || {
            log "ERROR adding ${_r%%:*} rule for $IP : $(first_line "$_out")"
            for _a in $_added; do ipt -D "${_a%%:*}" "${_a#*:}" "$IP" -j DROP >/dev/null 2>&1; done
            return 1
        }
        _added="$_added $_r"
    done
    if ! ipt_present; then
        log "ERROR: rules for $IP not found after adding them"
        for _a in $_added; do ipt -D "${_a%%:*}" "${_a#*:}" "$IP" -j DROP >/dev/null 2>&1; done
        return 1
    fi
    return 0
}

ipt_remove() {
    ipt_remove_all
    if ipt_leftover; then
        log "ERROR: a rule for $IP is still present after removal"
        return 1
    fi
    return 0
}

# --- nftables (own table, one set per address family) -------------------------

nft_set_name() {
    if [ "$FAMILY" = 6 ]; then echo blocked6; else echo blocked4; fi
}

nft_usable() {
    have nft && nft list tables >/dev/null 2>&1
}

# table and sets; "add" leaves existing ones untouched
nft_ensure_base() {
    nft -f - >/dev/null 2>&1 <<'NFT'
add table inet wazuh_ar
add set inet wazuh_ar blocked4 { type ipv4_addr; }
add set inet wazuh_ar blocked6 { type ipv6_addr; }
NFT
}

# creates chain $1 with its drop rules, unless it already exists
nft_ensure_chain() {
    nft list chain inet wazuh_ar "$1" >/dev/null 2>&1 && return 0
    case $1 in
        input)      _hook="input priority -10";       _dirs="saddr" ;;
        output)     _hook="output priority -10";      _dirs="daddr" ;;
        # raw priority: before conntrack and Docker's NAT, sees forwarded traffic
        prerouting) _hook="prerouting priority -300"; _dirs="saddr daddr" ;;
    esac
    {
        echo "add chain inet wazuh_ar $1 { type filter hook $_hook; policy accept; }"
        for _dir in $_dirs; do
            echo "add rule inet wazuh_ar $1 ip $_dir @blocked4 drop"
            echo "add rule inet wazuh_ar $1 ip6 $_dir @blocked6 drop"
        done
    } | nft -f - >/dev/null 2>&1
}

# is $IP an element of set $1? (reads the set back)
nft_has() {
    _re=$(printf '%s' "$IP" | sed 's/[.]/\\./g')
    nft list set inet wazuh_ar "$1" 2>/dev/null | tr '\n\t' '  ' |
        grep -Eq "[{ ,]$_re[ ,}]"
}

# adds $IP to set $1; adding an existing element is a no-op, so there is no gap
nft_add_element() {
    _out=$(nft add element inet wazuh_ar "$1" "{ $IP }" 2>&1) || {
        log "ERROR adding $IP to nft set $1 : $(first_line "$_out")"
        return 1
    }
    nft_has "$1" || {
        log "ERROR: $IP not found in nft set $1 after adding it"
        return 1
    }
    return 0
}

# removes $IP from set $1 if it is there, and checks that it is gone
nft_remove_element() {
    nft_has "$1" || return 0
    _out=$(nft delete element inet wazuh_ar "$1" "{ $IP }" 2>&1) ||
        debug "nft delete element said: $(first_line "$_out")"
    if nft_has "$1"; then
        log "ERROR: $IP is still in nft set $1 after removal"
        return 1
    fi
    return 0
}

nft_ensure_table() {
    nft_ensure_base &&
        nft_ensure_chain input &&
        nft_ensure_chain output &&
        nft_ensure_chain prerouting
}

nft_add() {
    nft_ensure_table || {
        log "ERROR: could not create nft table inet wazuh_ar"
        return 1
    }
    nft_add_element "$(nft_set_name)"
}

nft_remove() {
    if nft list table inet wazuh_ar >/dev/null 2>&1; then
        nft_remove_element "$(nft_set_name)"
    else
        debug "table inet wazuh_ar does not exist, nothing to remove"
    fi
}

# --- guard: forwarded traffic, host outbound, open connections ---------------
# Policy, the same whatever firewall is in use:
#   - runtime only: a reboot clears every block, like Wazuh's own timeouts
#   - both directions, for this host and for traffic it forwards (e.g. Docker)
#   - connections that are already open are cut
# The rules above only see traffic to and from this host, and on firewalld
# and ufw an established-connection accept comes first. The guard drops the
# address before connection tracking, Docker's NAT and those accepts:
#   nft backend      -> prerouting (raw priority) + output chains in inet wazuh_ar
#   firewalld        -> the same nft chains (firewalld reloads do not touch
#                       them), else iptables raw
#   ufw, iptables    -> iptables -t raw: PREROUTING -s/-d, OUTPUT -d
#   no raw table     -> DOCKER-USER (else FORWARD) -s/-d, plus filter OUTPUT -d
# The guard alone fully blocks an address unless it had to fall back, so on
# ufw it replaces ufw's persistent rules.

GUARD=""
GUARD_RULES=""
G_IPT=""
G_W=""
# every place an iptables guard rule may be, for unblock
GUARD_ALL_RULES="raw:PREROUTING:-s raw:PREROUTING:-d raw:OUTPUT:-d filter:DOCKER-USER:-s filter:DOCKER-USER:-d filter:FORWARD:-s filter:FORWARD:-d filter:OUTPUT:-d"

# the iptables tool for this address family, with -w when it is supported
guard_tool_init() {
    if [ "$FAMILY" = 6 ]; then G_IPT=ip6tables; else G_IPT=iptables; fi
    have "$G_IPT" || { G_IPT=""; return 1; }
    G_W=""
    "$G_IPT" -w -L -n >/dev/null 2>&1 && G_W="-w"
    return 0
}

gipt() {
    "$G_IPT" $G_W "$@"
}

# runs "gipt <op>" for a "table:chain:dir" rule
gipt_rule() {
    _t=${2%%:*}
    _rest=${2#*:}
    gipt -t "$_t" "$1" "${_rest%%:*}" "${_rest#*:}" "$IP" -j DROP
}

guard_select() {
    if [ "$BACKEND" = nft ] || { [ "$BACKEND" = firewalld ] && nft_usable; }; then
        GUARD=nft
        return 0
    fi
    if guard_tool_init; then
        if gipt -t raw -S PREROUTING >/dev/null 2>&1; then
            GUARD=iptables
            GUARD_RULES="raw:PREROUTING:-s raw:PREROUTING:-d raw:OUTPUT:-d"
            return 0
        fi
        for _chain in DOCKER-USER FORWARD; do
            if gipt -t filter -S "$_chain" >/dev/null 2>&1; then
                GUARD=iptables
                GUARD_RULES="filter:$_chain:-s filter:$_chain:-d filter:OUTPUT:-d"
                return 0
            fi
        done
    fi
    if nft_usable; then
        GUARD=nft
        return 0
    fi
    return 1
}

# does the guard alone block the address in both directions, open connections included?
guard_is_full() {
    [ "$GUARD" = nft ] && return 0
    case $GUARD_RULES in
        raw:*) return 0 ;;
    esac
    return 1
}

# removes every copy of the given iptables guard rules for $IP
guard_ipt_delete() {
    for _r in $1; do
        _n=0
        while [ "$_n" -lt 50 ] && gipt_rule -D "$_r" >/dev/null 2>&1; do
            _n=$((_n + 1))
        done
    done
}

guard_add() {
    if [ -z "$GUARD" ]; then
        log "WARNING: no iptables or nft available, forwarded traffic (e.g. Docker) to and from $IP is not blocked"
        return 0
    fi
    if [ "$GUARD" = nft ]; then
        # the nft backend's own set already feeds these chains
        [ "$BACKEND" = nft ] && return 0
        { nft_ensure_base && nft_ensure_chain prerouting && nft_ensure_chain output; } || {
            log "ERROR: could not create nft chains in table inet wazuh_ar"
            return 1
        }
        nft_add_element "$(nft_set_name)" || return 1
        log "Guard: $IP added to nft set inet wazuh_ar $(nft_set_name)"
        return 0
    fi
    # add only what is missing, so a repeated block never opens a gap
    _added=""
    for _r in $GUARD_RULES; do
        gipt_rule -C "$_r" >/dev/null 2>&1 && continue
        _out=$(gipt_rule -I "$_r" 2>&1) && gipt_rule -C "$_r" >/dev/null 2>&1 || {
            log "ERROR adding guard rule $_r for $IP : $(first_line "$_out")"
            for _a in $_added; do gipt_rule -D "$_a" >/dev/null 2>&1; done
            return 1
        }
        _added="$_added $_r"
    done
    log "Guard: $IP dropped with $G_IPT ($GUARD_RULES)"
    return 0
}

# removes $IP from every guard location, whichever one an earlier run used
guard_remove() {
    _status=0
    if guard_tool_init; then
        for _r in $GUARD_ALL_RULES; do
            _t=${_r%%:*}
            _rest=${_r#*:}
            gipt -t "$_t" -S "${_rest%%:*}" >/dev/null 2>&1 || continue
            guard_ipt_delete "$_r"
            if gipt_rule -C "$_r" >/dev/null 2>&1; then
                log "ERROR: guard rule $_r for $IP is still present after removal"
                _status=1
            fi
        done
    fi
    if have nft && nft list table inet wazuh_ar >/dev/null 2>&1; then
        nft_remove_element "$(nft_set_name)" || _status=1
    fi
    return $_status
}

# forgets the address's tracked connections, so no "established" state keeps
# an open connection alive past the block
flush_conntrack() {
    if ! have conntrack; then
        debug "conntrack not found; open connections with $IP are cut by the drop rules only"
        return 0
    fi
    if [ "$FAMILY" = 6 ]; then _f=ipv6; else _f=ipv4; fi
    for _dir in -s -d; do
        _out=$(conntrack -D -f "$_f" "$_dir" "$IP" 2>&1) &&
            log "conntrack $_dir $IP: $(printf '%s\n' "$_out" | sed -n '$p')"
    done
    return 0
}

# --- timers for manual blocks with a timeout ---------------------------------
# A detached "sleep, then unblock" process per address. Its token file names
# the newest block: a later block (with or without a timeout) or an unblock
# replaces or removes the file, and an outdated timer then does nothing.
# Timers do not survive a reboot, and neither do the blocks.

timer_file() {
    echo "$TIMER_DIR/$(printf '%s' "$IP" | tr ':' '_')"
}

cancel_timer() {
    rm -f "$(timer_file)"
}

schedule_unblock() {
    _file=$(timer_file)
    _token="$(date +%s).$$"
    { mkdir -p "$TIMER_DIR" && printf '%s\n' "$_token" > "$_file"; } || {
        log "ERROR: cannot write timer file $_file, $IP stays blocked until unblocked by hand"
        return 1
    }
    _msg=$(printf '{"version":1,"origin":{"name":"%s","module":"timer"},"command":"delete","parameters":{"extra_args":["unblock","%s"]}}' \
        "$SCRIPT_NAME" "$IP")
    # $1 seconds, $2 token file, $3 token, $4 message, $5 this script
    _job='sleep "$1"; [ "$(cat "$2" 2>/dev/null)" = "$3" ] || exit 0; rm -f "$2"; printf "%s\n" "$4" | sh "$5"'
    # detached and with no inherited pipes, so wazuh-execd does not wait for it
    if have setsid; then
        setsid sh -c "$_job" ar-timer "$ARG_TIMEOUT" "$_file" "$_token" "$_msg" "$SELF" \
            </dev/null >/dev/null 2>&1 &
    else
        nohup sh -c "$_job" ar-timer "$ARG_TIMEOUT" "$_file" "$_token" "$_msg" "$SELF" \
            </dev/null >/dev/null 2>&1 &
    fi
    log "Timer: $IP will be unblocked in ${ARG_TIMEOUT}s"
    return 0
}

# ---------------------------------------------------------------------------
# 5. Block / unblock with the detected firewall
# ---------------------------------------------------------------------------

add_ip_block() {
    log "ADD requested: IP=$IP firewall=$BACKEND"
    guard_select || GUARD=""
    case $BACKEND in
        firewalld) fwd_add || return 1 ;;
        ufw)
            if guard_is_full; then
                # persistent ufw rules would outlive a reboot and Wazuh's timeout
                log "ufw: blocking $IP with runtime rules outside ufw instead of persistent ufw rules"
            else
                log "WARNING: no iptables raw table or nft, falling back to persistent ufw rules for $IP"
                ufw_add || return 1
            fi
            ;;
        iptables)  ipt_add || return 1 ;;
        nft)       nft_add || return 1 ;;
    esac
    if ! guard_add; then
        if [ "$BACKEND" = ufw ] && guard_is_full; then
            log "ERROR: $IP is NOT blocked"
        else
            log "ERROR: $IP is blocked for this host but NOT for forwarded traffic"
        fi
        return 1
    fi
    flush_conntrack
    # the newest block decides when the address is released
    if [ "$MODE" = manual ] && [ -n "$ARG_TIMEOUT" ]; then
        schedule_unblock || return 1
    else
        cancel_timer
    fi
    log "SUCCESS: IP blocked: $IP firewall=$BACKEND${ARG_TIMEOUT:+ for ${ARG_TIMEOUT}s}"
    return 0
}

# Removes the address from every firewall that is available, not only the one
# detected now: the block may have been made while another one was in use
# (e.g. iptables while firewalld was stopped, or ufw before it was disabled).
remove_ip_block() {
    log "DELETE requested: IP=$IP firewall=${BACKEND:-none detected}"
    cancel_timer
    _rc=0
    _cleaned=""
    # a stopped firewalld has no runtime rules left to remove
    if have firewall-cmd && [ "$(firewall-cmd --state 2>/dev/null)" = running ]; then
        fwd_remove || _rc=1
        _cleaned="$_cleaned firewalld"
    fi
    # "ufw delete" also works while ufw is inactive, and removes persistent
    # rules from the fallback or an older version of this script
    if have ufw; then
        if [ "$BACKEND" = ufw ]; then
            ufw_remove || _rc=1
        else
            ufw_remove_quiet
        fi
        _cleaned="$_cleaned ufw"
    fi
    if guard_tool_init; then
        IPT=$G_IPT
        IPT_W=$G_W
        ipt_remove || _rc=1
        _cleaned="$_cleaned $G_IPT"
    fi
    if have nft && nft list table inet wazuh_ar >/dev/null 2>&1; then
        nft_remove || _rc=1
        _cleaned="$_cleaned nft"
    fi
    # clean the guard even when a host rule could not be removed
    guard_remove || _rc=1
    [ "$_rc" -eq 0 ] || return 1
    log "DELETE done: IP=$IP (checked:${_cleaned:- nothing to clean})"
    return 0
}

if [ "$OPERATION" = add ]; then
    detect_backend || fail "no usable firewall found (need a running firewalld or an active ufw, or iptables/ip6tables or nft, and root)"
    log "Firewall in use: $BACKEND"
    add_ip_block
else
    # unblock cleans every firewall it finds, so it goes ahead without one
    detect_backend || BACKEND=""
    log "Firewall in use: ${BACKEND:-none detected}"
    remove_ip_block
fi
exit $?
